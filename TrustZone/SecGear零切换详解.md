# 零切换技术详解

OpenEuler社区推出了机密计算套件secGear，来帮助开发人员更好的利用TEE。secGear针对CA侧需要频繁调用REE侧的场景，开发了零切换(switchless)技术，使用教程请参考[零切换demo](https://gitee.com/openeuler/secGear/blob/master/examples/switchless/README.md)。secGear未详细介绍技术实现的细节，因此本文针对TrustZone路线（基于iTrustee sdk）详细分析零切换技术的实现细节，供感兴趣的朋友参考。

## 原理描述
原理为在CA侧创建多个和TEE侧共享的内存区域，将共享内存区域注册到TEE侧。再额外创建一块共享内存区域来管理任务相关的状态，例如任务总数，空闲任务数，任务状态等。再通过对任务状态位原子修改和读取来监听任务状态，来触发TEE侧执行任务，以及REE侧获取任务执行成功。注意以下几个细节:
* TEE侧接收内存注册的接口不能退出，否则后续的共享内存无法在TEE侧使用。
* 共享内存在TEE侧和REE侧映射后的地址不一样，TEE需要知道共享内存在CA侧的内存，用于后续任务来计算在TEE侧偏移位置。

## 相关接口以及数据结构

数据结构

零切换配置，配置信息无需过多介绍，secGear文档有详细介绍。
```
typedef struct {
    /* number of untrusted (for ocalls) worker threads */
    uint32_t num_uworkers;

    /* number of trusted (for ecalls) worker threads */
    uint32_t num_tworkers;

    /* number of switchless calls pool size. (actual number is x 64) */
    uint32_t sl_call_pool_size_qwords;

    /* max number of parameters, only for GP */
    uint32_t num_max_params;

    /*
     * how many times to execute assembly pause instruction while waiting for worker thread to start executing
     * switchless call before falling back to direct ECall/OCall, only for SGX
     */
    uint32_t retries_before_fallback;

    /*
     * how many times a worker thread executes assembly pause instruction while waiting for switchless call request
     * before going to sleep, only for SGX
     */
    uint32_t retries_before_sleep;

    /* Worker thread scheduling policy, refer to cc_workers_policy_t, only for GP */
    uint32_t workers_policy;

    /* Indicates whether to roll back to common invoking when asynchronous switchless invoking fails, only for GP */
    uint32_t rollback_to_common;
} cc_sl_config_t;
```

零切换任务池，任务池结构详细描述见后续初始化任务池部分。
```
typedef struct {
    char *pool_buf; // switchless task pool control area, includes configuration area, signal bit area, and task area
    char *task_buf; // part of pool_buf, stores invoking tasks
    uint64_t *free_bit_buf; // length is bit_buf_size, the task indicated by the bit subscript is idle
    uint64_t *signal_bit_buf; // length is bit_buf_size, the task indicated by the bit subscript is to be processed
    uint32_t bit_buf_size; // size of each bit buf in bytes, determined by sl_call_pool_size_qwords in cc_sl_config_t
    uint32_t per_task_size; // size of each task in bytes, for details, see task[0]
    volatile bool need_stop_tworkers; // indicates whether to stop the trusted proxy thread
    cc_sl_config_t pool_cfg;
} sl_task_pool_t;
```

零切换任务，
```
typedef struct {
    //任务状态
    volatile uint32_t status;
    // 零切换任务函数在sl_ecall_func_table中的索引，该table由代码生成，详见后续介绍
    uint16_t func_id;
    //返回值大小
    uint16_t retval_size;
    //返回值
    volatile uint64_t ret_val;
    //输入参数，可以是值或者共享内存地址
    uint64_t params[0];
} sl_task_t;
```

CA侧部分相关接口
* gp_malloc_shared_memory 分配共享内存
* gp_register_shared_memory 注册共享内存到TEE模块
* uswitchless_create_task_pool 创建零切换任务池
* uswitchless_get_idle_task_index 获取任务池空闲任务ID
* uswitchless_put_idle_task_by_index 释放任务ID到任务池
* uswitchless_fill_task 设置任务参数，包括调用的TEE函数，入参和出参信息
* uswitchless_submit_task 提交任务到TEE侧执行
* uswitchless_get_task_result 获取任务执行结果
* init_uswitchless CA侧初始化零切换功能
* fini_uswitchless CA侧零切换功能析构

TEE侧部分相关接口
* tswitchless_init_pool 初始化零切换任务池
* tswitchless_init_workers 初始化零切换线程池
* tswitchless_fini 零切换任务析构
* ecall_register_shared_memory TEE接收注册共享内存入口函数

## 初始化零切换功能

分配共享内存详见init_uswitchless代码，主要流程为:

1. 首先根据零切换配置，获取零切换任务池所需的共享内存大小，函数为sl_get_pool_buf_len_by_config
1. 根据1计算出的大小，分配对应的共享内存，函数为gp_malloc_shared_memory，此处control_buf标志为true,分配共享内存详细细节见后续描述
1. 根据配置在CA侧创建任务池，函数为uswitchless_create_task_pool, 详见后续描述
1. 将任务池注册到TEE，函数为gp_register_shared_memory, 详见后续描述

## 分配共享内存

分配共享内存由gp_malloc_shared_memory函数实现，在iTrustee TEE平台，通过调用TEEC_AllocateSharedMemory来分配REE/TEE共享的内存。除了gp_malloc_shared_memory参数提供的共享内存大小，还会额外分配gp_shared_memory_t内存大小，用于记录该次分配的内存基础信息。gp_shared_memory_t段放在分配的共享内存开始部分，gp_malloc_shared_memory返回的地址为分配的地址 + sizeof(gp_shared_memory_t)

```
typedef struct {
    char shared_mem[GP_SHARED_MEMORY_SIZE]; // TEEC_SharedMemory 分配后的地址
    bool is_control_buf; // whether it is a control area; otherwise, it is the data area used by the user
    bool is_registered; // the shared memory can be used only after being registered
    void *enclave; // refer to cc_enclave_t
    pthread_t register_tid;
    list_node_t node; // 用于记录分配的共享内存列表
} gp_shared_memory_t;
```

## 初始化任务池
初始化任务池对应的函数为uswitchless_create_task_pool， 从函数实现可以看出，sl_task_pool_t包含三个部分：
1. CA侧分配的空间，用于保存sl_task_pool结构所需的内存空间。
2. CA侧额外分配了bit_buf_size用于记录任务分配情况，使用位图表示法，也就是该buf的每一个bit表示该bit对应的任务号是否未被分配。
3. 将pool_buf(也就是零切换初始化分配的shared memory）记录到 sl_task_pool_t结构中pool_buf字段，pool_buf 开始为cc_sl_config_t结构，随后为bit_buf_size大小的signal_bit_buf, 再最后为task_buf。

## CA侧注册共享内存
注册shared memory 对应的函数为gp_register_shared_memory，该函数流程为:
1. 首先检查注册的内存是否为共享内存
2. 其次检查零切换功能是否打开
3. 检查该共享内存是否已经注册过
4. 定义注册共享内存函数参数大小，由结构gp_register_shared_memory_size_t定义
5. 分配注册共享函数参数所需的空间，函数调用如下
```
 /* Calculate the input parameter offset. */
    size_t in_param_buf_size = size_to_aligned_size(sizeof(args_size));
    PARAM_OFFSET_MOVE(in_param_buf_size, ptr_offset, args_size.shared_buf_size);
    PARAM_OFFSET_MOVE(in_param_buf_size, ptr_len_offset, args_size.shared_buf_len_size);
    PARAM_OFFSET_MOVE(in_param_buf_size, is_control_buf_offset, args_size.is_control_buf_size);

    /* Calculate the output parameter offset. */
    size_t out_param_buf_size = 0;
    PARAM_OFFSET_MOVE(out_param_buf_size, retval_offset, args_size.retval_size);
 
    /* Allocate in_buf and out_buf */
    char *param_buf = (char *)calloc(in_param_buf_size + out_param_buf_size, sizeof(char));
     if (param_buf == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    char *in_param_buf = param_buf;
    char *out_param_buf = param_buf + in_param_buf_size;

    /* Copy in_params to in_buf */
    memcpy(in_param_buf, &args_size, size_to_aligned_size(sizeof(args_size)));
    memcpy(in_param_buf + ptr_offset, &ptr, sizeof(void*));
    size_t shared_mem_size = ((TEEC_SharedMemory *)(&gp_shared_mem->shared_mem))->size - sizeof(gp_shared_memory_t);
    memcpy(in_param_buf + ptr_len_offset, &shared_mem_size, sizeof(size_t));
    memcpy(in_param_buf + is_control_buf_offset, &gp_shared_mem->is_control_buf, sizeof(bool));
```
可以看出该空间的内存布局为，最开始部分为sizeof(gp_register_shared_memory_size_t)结构，该结构定义了返回值大小、shared_buf指针大小（注意不是shared buf大小，而是指针大小），shared_buf长度大小，以及control_buf_size的大小。接着为shared_buf地址值、shared_buf的长度、是否为shared_buf、最后为预留的返回值空间。

6. 随后调用handle_ecall_function_register_shared_memory注册共享内存。
```
    cc_enclave_call_function_args_t args;

    args.function_id = 0;
    args.input_buffer = in_param_buf;
    args.input_buffer_size = in_param_buf_size;
    args.output_buffer = out_param_buf;
    args.output_buffer_size = out_param_buf_size;
    args.output_bytes_written = 0;
    args.result = CC_FAIL;
    args.enclave = enclave;
    
    cc_enclave_result_t ret = handle_ecall_function_register_shared_memory(enclave, &args);
    /* Copy out_buf to out_params */
    int retval = 0;
    (void)memcpy(&retval, out_param_buf + retval_offset, sizeof(int));
    if (retval != (int)CC_SUCCESS) {
        free(param_buf);
        return CC_FAIL;
    }
```
TEE侧 注册shared_memory对应的function_id 为 fid_register_shared_memory（0）， input_buffer 和 output_buffer 为上述5设置的参数信息。

handle_ecall_function_register_shared_memory 内创建一个新的线程来注册共享内存，新线程的工作函数为handle_ecall_function_with_new_session。该函数流程下:
* TEEC_OpenSession 打开TA Session
* 调用init_operation配置TA调用参数，该函数内部检查调用函数是否为fid_register_shared_memory。如果是，则将TEEC_InvokeCommand第三个参数设置为分配的shared_memory 地址，参数类型为TEEC_MEMREF_SHARED_INOUT。
* TEEC_InvokeCommand调用TA侧SECGEAR_ECALL_FUNCTION 命令

## TEE侧接收注册信息

TrustZone TA侧 接收注册shared memory的函数入口为ecall_register_shared_memory，该函数在编译时通过代码生成后嵌入到secGear TA程序中，对应的产生代码函数为tools/codegener/Gentrust.ml 中gen_trusted 函数，定义如下:

```
let gen_trusted(ec : enclave_content) = 
    let trust_funcs = ec.tfunc_decls in
    let untrust_funcs = ec.ufunc_decls in
    let ocall_func = List.flatten (List.map set_ocall_func untrust_funcs) in
    let ecall_func = List.flatten (List.map set_ecall_func trust_funcs) in
    let ecall_table = 
        [
            "extern cc_enclave_result_t ecall_register_shared_memory(uint8_t *in_buf, size_t in_buf_size,";
            "    uint8_t *out_buf, size_t out_buf_size, uint8_t *shared_buf, size_t *output_bytes_written);";
            "extern cc_enclave_result_t ecall_unregister_shared_memory(uint8_t *in_buf, size_t in_buf_size,";
            "    uint8_t *out_buf, size_t out_buf_size, uint8_t *shared_buf, size_t *output_bytes_written);\n";
            "cc_ecall_func_t cc_ecall_tables[] = {";
            "    (cc_ecall_func_t) ecall_register_shared_memory,";
            "    (cc_ecall_func_t) ecall_unregister_shared_memory,";
            "    " ^ concat ",\n    "
                (List.map (fun (tf) ->
                    sprintf "(cc_ecall_func_t) ecall_%s" tf.tf_fdecl.fname) trust_funcs);
            "};";
            "";
            "size_t ecall_table_size = CC_ARRAY_LEN(cc_ecall_tables);\n";
        ]
    in
    ...
```

如上所示，ecall_register_shared_memory、ecall_unregister_shared_memory和其他用户自定义的trusted function定义在cc_ecall_tables 数组中，ecall_register_shared_memory索引为0，ecall_unregister_shared_memory索引为1。而在handle_ecall_function函数中，会按照用户上传的function_id, 调用对应的trusted function。 代码如下所示：
```
static TEE_Result handle_ecall_function(uint32_t param_types, TEE_Param params[PARAMNUM])
{
    ...

    args_ptr = (cc_enclave_call_function_args_t *)params[POS_IN_OUT].memref.buffer;

    ecall_table.ecalls = cc_ecall_tables;
    ecall_table.num = ecall_table_size;

    if (args_ptr->function_id >= ecall_table.num)
        return TEE_ERROR_ITEM_NOT_FOUND;

    func = ecall_table.ecalls[args_ptr->function_id];
    if (func == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    tmp_input_buffer_size = params[POS_IN].memref.size;
    tmp_output_buffer_size = params[POS_OUT].memref.size;
    res = get_params_buffer(params, &tmp_input_buffer, &tmp_output_buffer);
    if (res != CC_SUCCESS)
        goto done;
    /* call the ecall function */
    res = func(tmp_input_buffer,
               tmp_input_buffer_size,
               tmp_output_buffer,
               tmp_output_buffer_size,
               params[POS_SHARED_MEM].memref.buffer, //需要注意此处，为上述CA侧init_operation添加的第三个参数
               &output_bytes_written);
    ...
}
```

需要注意的是，在调用trusted function时，将CA侧init_operation添加的第三个shared_memory指针传入，而且此处shared_memory已经转化为TA侧映射的虚拟地址，在TA侧可以使用此地址进行读写操作。

ecall_register_shared_memory 函数实现如下
```
cc_enclave_result_t ecall_register_shared_memory(uint8_t *in_buf,
                                                 size_t in_buf_size,
                                                 uint8_t *out_buf,
                                                 size_t out_buf_size,
                                                 uint8_t *registered_buf,
                                                 size_t *output_bytes_written)
{
    ...
    //读取shared memory 在host侧地址
    SET_PARAM_IN_1(host_buf_p, size_t, host_buf, args_size->shared_buf_size);
    SET_PARAM_IN_1(host_buf_len_p, size_t, host_buf_len, args_size->shared_buf_len_size);
    SET_PARAM_IN_1(is_control_buf_p, bool, is_control_buf, args_size->is_control_buf_size);

    /* Fill return val, out and in-out parameters */
    size_t out_buf_offset = 0;

    uint8_t *retval_p = NULL;
    SET_PARAM_OUT(retval_p, int, retval, args_size->retval_size);
    
    // registered_buf为 shared memory 在TEE侧地址，
    *retval = itrustee_register_shared_memory((void *)host_buf, host_buf_len, registered_buf, is_control_buf);
    *output_bytes_written = out_buf_offset;

    return CC_SUCCESS;
}

```


itrustee_register_shared_memory 代码如下所示， TA侧也分配结构记录shared memory 信息，并且如果是control_buf, 则通过tswitchless_init 分配对应的工作线程，相关细节请参考tswitchless_init代码实现。 shared_memory注册函数不会退出，直到shared_memory 注销。

```
static cc_enclave_result_t itrustee_register_shared_memory(void *host_buf,
                                                           size_t host_buf_len,
                                                           void *registered_buf,
                                                           bool is_control_buf)
{
    cc_enclave_result_t ret = CC_FAIL;

    shared_memory_block_t *shared_mem = create_shared_memory_block(host_buf, host_buf_len, registered_buf);
    ...
    if (is_control_buf) {
        ret = tswitchless_init((void *)shared_mem->enclave_addr, &shared_mem->pool, &shared_mem->tid_arr);
        ...
    }

    add_shared_memory_block_to_list(shared_mem);
    __atomic_store_n(&(((gp_shared_memory_t *)registered_buf)->is_registered), true, __ATOMIC_RELEASE);

    // 等待shared memory 注销，否则函数一直等待
    CC_MUTEX_LOCK(&shared_mem->mtx_lock);
    CC_COND_WAIT(&shared_mem->unregister_cond, &shared_mem->mtx_lock);
    CC_MUTEX_UNLOCK(&shared_mem->mtx_lock);

    __atomic_store_n(&(((gp_shared_memory_t *)registered_buf)->is_registered), false, __ATOMIC_RELEASE);
    remove_shared_memory_block_from_list(shared_mem);

    if (is_control_buf) {
        tswitchless_fini(shared_mem->pool, shared_mem->tid_arr);
    }

    destroy_shared_memory_block(shared_mem);

    return CC_SUCCESS;
}
```

## CA侧提交任务

CA侧发起任务的流程为
1. 首先通过uswitchless_get_idle_task_index 来分配空闲任务索引
2. 通过uswitchless_fill_task 来设置任务的参数，包括任务索引， TA侧任务处理函数，任务参数，任务返回值大小
3. 调用uswitchless_submit_task通知TA侧开始执行任务

从uswitchless_get_idle_task_index实现可以看出，sl_task_pool_t中的free_bit_buf通过位图法来记录和分配哪些索引位置已经使用。uswitchless_get_idle_task_index的核心就是从free_bit_buf来寻找未分配的索引号。uswitchless_submit_task 会将task_pool 中signal_bit设置为1。而uswitchless_fill_task函数中args参数为共享内存数组，值为已分配shared memory中任意合法地址均可; 当然，也可以为基本值类型。


## TEE侧接收任务

TEE侧工作线程的主函数为tswitchless_thread_routine，代码如下所示

```
static void *tswitchless_thread_routine(void *data)
{
    int thread_index = __atomic_add_fetch(&thread_num, 1, __ATOMIC_ACQ_REL);
    SLogTrace("Enter tworkers: %d.", thread_index);

    int task_index;
    sl_task_t *task_buf = NULL;
    sl_task_pool_t *pool = (sl_task_pool_t *)data;
    int processed_count = 0;
    bool is_workers_policy_wakeup = tswitchless_is_workers_policy_wakeup(&(pool->pool_cfg));
    ...

    while (true) {
        if (pool->need_stop_tworkers) {
            break;
        }

        count++;
        task_index = tswitchless_get_pending_task(pool);
        if (task_index == -1) {
           ...

            continue;
        }

        task_buf = tswitchless_get_task_by_index(pool, task_index);
        __atomic_store_n(&task_buf->status, SL_TASK_ACCEPTED, __ATOMIC_RELEASE);
        tswitchless_proc_task(task_buf);

        processed_count++;
    }

   ...
}

```

如上所示，任务主函数通过tswitchless_get_pending_task 来获取需要执行的任务，switchless_get_pending_task通过扫描signal_bit来获取需要执行的任务index。再通过tswitchless_proc_task执行任务。 tswitchless_proc_task 代码如下:

```
extern const sl_ecall_func_t sl_ecall_func_table[];
extern const size_t sl_ecall_func_table_size;

static void tswitchless_proc_task(sl_task_t *task)
{
    uint32_t function_id = task->func_id;
    ...

    sl_ecall_func_t func = sl_ecall_func_table[function_id];
    ...

    func(task);
    __atomic_store_n(&task->status, SL_TASK_DONE_SUCCESS, __ATOMIC_RELEASE);
}
```

可以看出通过查找sl_ecall_func_table 来调用零切换任务，并且在任务执行结束/出错时通过设置任务status值来通知CA侧任务执行结束。 而func(task) 为调用具体的零切换任务，详情可以参考编译时自动生成的代码，包括gen_trusted 和set_sl_call_params。 代码如下:
```
文件tools/codegener/Gentrust.ml

let gen_trusted(ec : enclave_content) = 
    ...
    //此处定义 sl_ecall_table
    let sl_ecall_table =
        [
            "\n/* switchless ECALL table */";
            "sl_ecall_func_t sl_ecall_func_table[] = {";
            "    " ^ concat ",\n    "
                (List.map
                    (fun (tf) -> sprintf "(sl_ecall_func_t) sl_ecall_%s" tf.tf_fdecl.fname)
                    (List.filter (fun tf -> tf.tf_is_switchless) trust_funcs));
            "};\n";
            "size_t sl_ecall_func_table_size = CC_ARRAY_LEN(sl_ecall_func_table);\n";
        ]
    in
    [
        "";
        sprintf "#include \"%s_t.h\"" ec.file_shortnm;
        "";
        "#include <stdio.h>";
        "#include <string.h>";
        "#include \"secgear_defs.h\"";
        "";
        "/*";
        " * Summary: Switchless bridge function prototype on the security side";
        " * Parameters:";
        " *     task_buf: task buf, refer to sl_task_t";
        " * Return: NA";
        " */";
        "typedef void (*sl_ecall_func_t)(void *task_buf);\n";
        "extern size_t addr_host_to_enclave(size_t addr);";
        // 此处定义从fill_task args参数来获取值类型
        "#define SL_GET_VAL_PARAM_FROM_TASK_BUF(var_type) \\";
        "    (var_type)(*(var_type *)(task_params++))";

        // 此处定义从fill_task args参数来获取共享内存数据，注意此处将CA侧的地址通过注册时的映射关系，转换成TA侧的地址
        "#define SL_GET_PTR_PARAM_FROM_TASK_BUF(var_type) \\";
        "    (var_type)addr_host_to_enclave((size_t)((var_type)(*(var_type *)(task_params++))))\n";
        " /* ECALL FUNCTIONs */";
        concat "\n" ecall_func;
        "";
        "/* set_caller_ca_owner*/";
        concat "\n" g_caller_ca_owner;
        "";
        " /* OCALL FUNCTIONs */";
        if (List.length untrust_funcs <> 0 ) then concat "\n" ocall_func ^"\n"
        else "/* There is no ocall functions */\n";
        concat "\n" ecall_table;
        concat "\n" sl_ecall_table;
        "";
    ]

    __________________________________________
    文件tools/codegener/Commonfunc.ml
    let set_sl_call_params (fd : func_decl) =
    let pl = fd.plist in
        [
            "/* get switchless function params from task buf */\n    " ^ concat "\n    "
            (List.map
                (fun(ptype, decl) ->
                    let var_type = get_tystr2 (get_param_atype ptype) in
                    let var_name = decl.identifier in
                        match ptype with
                        | PTVal _ ->
                            sprintf "%s %s = SL_GET_VAL_PARAM_FROM_TASK_BUF(%s);" var_type var_name var_type
                        | PTPtr (t, a) ->
                            sprintf "%s *%s = SL_GET_PTR_PARAM_FROM_TASK_BUF(%s *);" var_type var_name var_type)
                pl) ^ "\n";
        ]
```

## CA侧获取任务结果

CA侧uswitchless_get_task_result 则通过监听task status值来判断任务是否执行结束。如果检查时间超时，该函数也会退出。

