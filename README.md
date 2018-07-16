# MachOA

入口位于：angrTest/main.py 

analyzer = Analyzer('../samples/ToGoProject') # 输入：MachO 二进制文件
analyzer.data_init() # 类数据解析
analyzer.analyze_function(0x1000C232C) #待测方法地址

结果：
该方法内的API调用序列

例如以下为一次完整的调用序列，通常情况下由于跳转分支，存在多个调用序列：
0x1000c232c Start-> 0x1000c23c8L [_OBJC_CLASS_$_NSMutableDictionary dictionaryWithDictionary:]-> 0x1000c23e8L [TGHttpManager setCommonParametresWithDict:]-> 0x1000c24ccL [uninitialized_x0_31_64 setObject:forKeyedSubscript:]-> 0x1000c24e0L [0 length]-> 0x1000c24f4L [0 substringToIndex:]-> 0x1000c2510L [uninitialized_x0_43_64 stringByAppendingString:]-> 0x1000c2544L [TGHttpManager LogRequestInfoWithURLString:parameters:name:]-> 0x1000c2618L [TGEncryptHelper AESKeyWithSuccess:]-> 0x1000c262cL [uninitialized_x0_79_64 length]-> 0x1000c2658L [TGHttpManager queryStringFromParameters:]-> 0x1000c2674L [uninitialized_x0_90_64 dataUsingEncoding:]-> 0x1000c269cL [TGEncryptHelper AESIVString]-> 0x1000c26c4L [uninitialized_x0_99_64 AES128EncryptWithKey:ivString:]-> 0x1000c26e4L [TGEncryptHelper AESIVString]-> 0x1000c270cL [uninitialized_x0_123_64 AES128DecryptWithKey:ivString:]-> 0x1000c2734L [_OBJC_CLASS_$_NSString alloc]-> 0x1000c274cL [uninitialized_x0_165_64 initWithData:encoding:]-> 0x1000c2798L [TGHttpManager setHeaderFieldWithIsEncrypt:]-> 0x1000c28c0L [TGHttpManager POSTWithURLString:parameters:success:failure:]-> End

待解决问题：
1. 返回值：通常情况下函数调用应跳转到该method的imp，但考虑到效率问题，目前暂时将返回值置为为初始化寄存器，以保证覆盖所有执行路径；
2. 循环：循环的限制应该使用LoopSeer，但需要cfg，目前angr貌似不支持macho的cfg生成；



