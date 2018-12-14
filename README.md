# MachOA


```
analyzer = MachOTask('../samples/AppJobber_arm64', store=True, visualize=False)
# 对实现了CLLocationManagerDelegate协议的类（方法），模拟事件触发解析
CLDriver(analyzer).simulate()
analyzer.clear()
```
结果示例：  

```
--------------------------------------------------------------------------------
0x100260f10 +[UIDevice currentDevice]
Receiver: UIDevice 
Arguments:
--------------------------------------------------------------------------------
0x100260f1c -[[UIDevice currentDevice] identifierForVendor]
Receiver: (@"UIDevice"<RET:0x100260f10L>)[UIDevice currentDevice] 
Arguments:
--------------------------------------------------------------------------------
0x100260f30 -[[[WXOMTAEnv alloc] init] setIfv:]
Receiver: (@"WXOMTAEnv"<RET:0x100260e8cL>)[[WXOMTAEnv alloc] init] 
Arguments:
para0: (unknown<RET:0x100260f1cL>)[[UIDevice currentDevice] identifierForVendor]

```


### 如何判断UIEvent的响应方法
1. 继承UIResponder的类所实现的事件处理方法；  
2. addTarget:action:forControlEvents:调用中target对象的action方法；  
从event_simulator/UIEvent.py入手。  


### 注意对象的构造表达式
instance_types = {
​    'PARA': 'passed_in_as_parameter',
​    'REC': 'as_receiver',
​    'RET': 'as_ret_value',
​    'IVAR': 'ret_as_ivar'
}
FORMAT_INSTANCE = '({data_type}<{instance_type}:{ptr}>){name}'

### 数据的产生
#### from RuntimePatch.message import Func
初始化寄存器，主要看方法是否为instance method，若是将X0初始化为该instance（添加随机数）。arguments的来源有两个，一是可以通过Func(args=...)传入指定类型；二是查看该方法是否为协议方法（因为协议定义的方法在MachO中有类型），同样添加随机数标识该对象；否则，使用Pn作为名称。

#### from RuntimePatch.message import Messgae
在执行过程中，需要关注的是返回值的生成。
根据FORMAT_INSTANCE = '({data_type}<{instance_type}:{ptr}>){name}'，返回值需要主要几个数据：  
1. 返回值类型：如果能对调用进行解析，查看该调用的meth_type获得返回值类型；否则计作'unknown'；
2. instance_type为'RET'，ptr为该调用的地址；
3. name，表示为调用的表达，即[receiver selector]的形式。

#### 对返回值类型的查找：  
1. 依据协议；receiver
2. 依据methtype ;
3. unknown；

### 数据的表示以及解析
#### from Data.data.py import Data
(￣▽￣) 这个名字太不友好了。  
数据的解析尽量统一使用该类来完成。主要解析包括：  
1. 根据寄存器类型进行数据表示，如果是BVV，解析所属段、数据类型，获得合适的表达；如果是BVS，比较简单的使用'_'.join(args[0].split('_')[0:-2])方法，因为BVS自带的_?_?随机表示。
2. 还有一个关键内容，是栈地址的解析。

#### from Data.data.py import SEL
def __init__(self, data)
其实就是在Data数据上，进一步进行selector相关的解析。例如，参数的解析（已知state，selector，可以确定参数的个数；或者selector是stringWithFormat:时）。

#### from Data.data.py import Receiver
def __init__(self, data, sel)
注意这里sel是必要的参数，因为对一次调用来说，selector是很容易被确认的。  
同时，当receiver类型无法确认时，通过selector对其进行类型推断。  

receiver的类型：  
1. BVV, classdata_ea，类方法调用
2. BVV, string，为字符串，实例方法调用
3. BVS，符号表示，需要进行类型提取／推断

#### 注意reciever类型推断与返回值推断

receiver类型推断发生在dynamic_bind，根据selector推断receiver；  
返回值推断发生在过程间分析，当需要过程间分析时，直接解析调用，进入另一进程；当无需过程间分析时，对返回值进行合理表示，在OCFunction.find_detailed_prototype中进行推断，根据receiver类型和selector进行解析。  
```python
# 在此处进行receiver类型推断，尽可能确定({data_type}<{instance_type}:{ptr}>){name}'中的
# data_type
self.receiver = Receiver(Data(self.dispatch_state, reg=self.dispatch_state.regs.x0),
                                 self.selector)
# 返回值类型的推断，是一定需要receiver类型已确定的情况，否则为unknown；
# 通常是依据protocol_methtype, methtype, 预定义的alloc, init, currentDevice等；
ret_type = OCFunction.find_detailed_prototype(self.selector.expr, self.receiver.oc_class)[0]
```








