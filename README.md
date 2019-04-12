# MachOA

【测试中】
1. 安装angr，直接pip install angr即可；由于当前的cle库对Mach-O二进制的解析支持有问题（待确认），因此在安装angr后重新安装7.8.7.1版本的cle：pip install cle==7.8.7.1。
2. 配置文件为config/config0，关键路径包括：
    ida_path: IDA（64）可执行文件的绝对路径；
    ida_script: 用于解析Mach-O二进制中引用关系的脚本，是Mach-O项目中tools/IDAScript_xrefs.py文件，可移动，在此处填写绝对路径；
    dbs: 数据库所在文件夹路径，每对一个Mach-O二进制进行解析会生成两个.pkl文件存储二进制的信息（首次解析时生成），一个是使用IDA脚本生成的引用关系，另一个则是类、方法、实例变量、协议等信息；
    results: 测试结果所在文件夹路径.   
3. python Scheduler.py Mach-O文件路径 待测试的方法起始地址 （对该方法进行符号执行，获得执行树输出为.dot文件到results路径中）     
    或者      
   python Scheduler.py Mach-O文件路径 receiver selector 模式 （根据receiver和selector查找该方法的调用者，对每个调用者实施解析。）   
   模式有三种：   
   MSG，receiver与selector同时出现的代码片段视作可疑调用者；   
   SEL，完全依赖selector，当selector十分特殊时可以使用该模式，init之类的就别了；   
   ADJ，适配模式，二者之间，大家可以查看代码自己调整。  
4. 符号执行有个“IPC”开关，决定是否在符号执行过程中实现过程间路径。（开关、常量大多在Data/CONSTANTS.py中，大家可以查找其引用查看代码逻辑）慎用，不好控制。
5. Mach-O二进制只支持arm64，有必要的话先脱壳再lipo。


【给师妹】   
RuntimePatch/message.py中，（Message就是模拟出的message对象，每当objc_msgSend函数执行时处理的消息）  
send2方法里，（模拟消息发送）   
有一句insert_invoke，是将当前消息的信息作为调用节点录入执行树里面（最后会被输出为dot文件），你在这里开调试看下数据结构，可以写一个解析器来看是否调用了敏感API。   
这样匹配其实有点粗糙，因为是单个过程内做解析，没有上下文信息，比如你一个消息的receiver依赖于上文的调用或者传入的参数，按理说应该再做个数据类型追踪、更新，那部分在污点分析那边...  
这个你先凑合用。    

   
    






