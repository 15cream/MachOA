# coding=utf-8

SEC_RULES = {
    'Payment': [
        {
            'Receiver': 'PKPaymentAuthorizationController',
            'Selector': 'canMakePayments',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '当返回值为True，表示用户可付款；该调用表示应用可能存在支付行为。'
        },
        {
            'Receiver': 'PKAddPaymentPassRequest',
            'Selector': 'init',
            'Arguments': None,
            'RET': 'id',
            'Description': '初始化支付。'
        },
        {
            'Receiver': 'PKPaymentAuthorizationController',
            'Selector': 'canMakePaymentsUsingNetworks:',
            'Arguments': 'NSArray<PKPaymentNetwork>',
            'RET': 'BOOL',
            'Description': '...'
        },
        {
            'Receiver': 'SKPaymentQueue',
            'Selector': 'canMakePayments',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '可以限制iPhone访问Apple App Store。例如，父母可以限制孩子购买额外内容的能力。您的应用程序应确认在向队列添加付款之前允许用户授权付款。当不允许用户授权付款时，您的应用程序可能还希望更改其行为或外观。'
        },
        {
            'Receiver': 'PKAddPaymentPassViewController',
            'Selector': 'canAddPaymentPass',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '返回一个布尔值，指示应用程序是否可以向Apple Pay添加卡。'
        },
        {
            'Receiver': 'PKSuicaPassProperties',
            'Selector': 'passPropertiesForPass:',
            'Arguments': 'PKPass',
            'RET': 'id',
            'Description': '实例化Suica传递属性对象，该对象包含指定传递中支持的属性'
        },
        {
            'Receiver': 'SKPaymentTransactionObserver',
            'Selector': 'paymentQueue:updatedTransactions:',
            'Arguments': '(SKPaymentQueue *)queue,(NSArray<SKPaymentTransaction *> *)transactions',
            'RET': None,
            'Description': '应用程序应通过检查事务的属性来处理每个事务。如果是SKPaymentTransactionStatePurchased，则已成功收到所需功能的付款。应用程序应该使用户可以使用该功能。如果是SKPaymentTransactionStateFailed，则应用程序可以读取事务的error属性以向用户返回有意义的错误。'

        }
    ],
    'Siri': [
        {
            'Receiver': 'INPreferences',
            'Selector': 'requestSiriAuthorization',
            'Arguments': 'block',  # void (^)(INSiriAuthorizationStatus status)
            'RET': None,
            'Description': '请求授权使用Siri服务'
        }
    ],
    'Ad_tracking': [
        {
            'Receiver': 'ASIdentifierManager',
            'Selector': 'advertisingIdentifier',
            'Arguments': None,
            'RET': 'NSUUID',
            'Description': '每个设备唯一的字母数字字符串，仅用于投放广告'
        },
        {
            'Receiver': 'ASIdentifierManager',
            'Selector': 'advertisingTrackingEnabled',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '一个布尔值，指示用户是否具有有限的广告跟踪。'
        }
    ],
    'Health': [
        {
            'Receiver': 'HKHealthStore',
            'Selector': 'dateOfBirthComponentsWithError:',
            'Arguments': 'NSError',
            'RET': 'NSDateComponents',
            'Description': '从HealthKit商店读取用户的出生日期。'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'bloodTypeWithError:',
            'Arguments': 'NSError',
            'RET': 'HKBloodTypeObject',
            'Description': '从HealthKit商店读取用户的血型。'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'biologicalSexWithError:',
            'Arguments': 'NSError',
            'RET': 'HKBiologicalSexObject',
            'Description': '从HealthKit商店读取用户的生物性别。'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'fitzpatrickSkinTypeWithError:',
            'Arguments': 'NSError',
            'RET': 'HKFitzpatrickSkinTypeObject',
            'Description': '从HealthKit商店读取用户的Fitzpatrick皮肤类型'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'isHealthDataAvailable',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': 'YES如果HealthKit可用; 否则，NO'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'biologicalSexWithError:',
            'Arguments': 'NSError',
            'RET': 'HKBiologicalSexObject',
            'Description': 'biologicalsex'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'supportsHealthRecords',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '返回一个布尔值，指示当前设备是否支持临床记录'
        }, {
            'Receiver': 'HKQuery',
            'Selector': 'predicateForClinicalRecordsFromSource:FHIRResourceType:identifier:',
            'Arguments': 'HKSource,HKFHIRResourceType,NSString',
            'RET': 'NSPredicate',
            'Description': '临床记录的谓语词来源'
        }, {
            'Receiver': 'HKQuery',
            'Selector': 'predicateForClinicalRecordsWithFHIRResourceType:',
            'Arguments': 'HKFHIRResourceType',
            'RET': 'NSPredicate',
            'Description': '临床记录的谓语词来源'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'wheelchairUseWithError:',
            'Arguments': 'NSError',
            'RET': 'HKWheelchairUseObject',
            'Description': '是否坐轮椅'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'addSamples:toWorkout:completion:',
            'Arguments': 'NSArray,HKWorkout,block',  # void (^)(BOOL success, NSError *error)
            'RET': None,
            'Description': '将提供的样本与指定的锻炼相关联'
        }, {
            'Receiver': 'HKWorkoutBuilder',
            'Selector': 'addSamples:completion:',
            'Arguments': 'NSArray,block',  # void (^)(BOOL success, NSError *error)
            'RET': None,
            'Description': '添加与锻炼相关联的样本。'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'splitTotalEnergy:startDate:endDate:resultsHandler:',
            'Arguments': 'HKQuantity,NSDate,NSDate,block',
            # (void (^)(HKQuantity *restingEnergy, HKQuantity *activeEnergy, NSError *error))
            'RET': None,
            'Description': '根据给定持续时间内燃烧的总能量计算燃烧的活动能量和静止能量。'
        }
    ],
    'calendar': [
        {
            'Receiver': 'UNCalendarNotificationTrigger',
            'Selector': 'triggerWithDateMatchingComponents:repeats:',
            'Arguments': '(NSDateComponents *)dateComponents,(BOOL)repeats',
            'RET': 'id',
            'Description': '基于指定时间信息的新日历触发器'
        }, {
            'Receiver': 'EKEventStore',
            'Selector': 'requestAccessToEntityType:completion:',
            'Arguments': 'EKEntityType,EKEventStoreRequestAccessCompletionHandler',
            'RET': None,
            'Description': '提示用户授予或拒绝访问事件或提醒数据。'
        }, {
            'Receiver': 'EKEvent',
            'Selector': 'eventWithEventStore:',
            'Arguments': 'EKEventStore',
            'RET': 'EKEvent',
            'Description': '创建并返回属于指定事件存储的新事件。'
        }, {
            'Receiver': 'EKRecurrenceRule',
            'Selector': 'initRecurrenceWithFrequency:interval:end:',
            'Arguments': 'EKRecurrenceFrequency,NSInteger,EKRecurrenceEnd',
            'RET': 'id',
            'Description': '创建重复事件。'
        }, {
            'Receiver': 'EKCalendarItem',
            'Selector': 'addAlarm:',
            'Arguments': 'EKAlarm',
            'RET': None,
            'Description': '添加闹钟。'
        }, {
            'Receiver': 'EKEventStore',
            'Selector': 'saveEvent:span:error:',
            'Arguments': 'EKEvent,EKSpan,NSError',
            'RET': 'bool',
            'Description': '永久保存对事件的更改。'
        }, {
            'Receiver': 'EKReminder',
            'Selector': 'reminderWithEventStore:',
            'Arguments': 'EKEventStore',
            'RET': 'EKReminder',
            'Description': '在给定的事件存储中创建并返回新的提醒'
        }
    ],
    'music': [
        {
            'Receiver': 'SKCloudServiceController',
            'Selector': 'requestAuthorization',
            'Arguments': 'block',  # void (^)(SKCloudServiceAuthorizationStatus status)
            'RET': None,
            'Description': '您可以使用此方法询问用户是否允许播放Apple Music曲目或将曲目添加到音乐库'
        }, {
            'Receiver': 'SKCloudServiceController',
            'Selector': 'authorizationStatus',
            'Arguments': None,
            'RET': 'SKCloudServiceAuthorizationStatus',
            'Description': '音乐库访问的授权类型。有关可能值的列表'
        }, {
            'Receiver': 'MPMusicPlayerController',
            'Selector': 'prepareToPlayWithCompletionHandler:',
            'Arguments': 'NSError',  # void (^)(NSError *error)
            'RET': None,
            'Description': '在队列中的第一个项目之后调用的块被缓冲并准备好播放。'
        }, {
            'Receiver': 'MPSystemMusicPlayerController',
            'Selector': 'openToPlayQueueDescriptor:',
            'Arguments': 'MPMusicPlayerQueueDescriptor',
            'RET': None,
            'Description': '打开音乐应用并播放指定的视频。'
        }
    ],
    'microphone': [
        {
            'Receiver': 'SFSpeechRecognizer',
            'Selector': 'init',
            'Arguments': None,
            'RET': 'id',
            'Description': '创建与用户的默认语言设置关联的语音识别器。'
        },
        {
            'Receiver': 'SFSpeechRecognizer',
            'Selector': 'initWithLocale',
            'Arguments': '(NSLocale *)locale',
            'RET': None,
            'Description': '区域设置对象，表示要用于语音识别的语言。有关语音识别器支持的语言列表。'
        },

        {
            'Receiver': 'SFSpeechRecognizer',
            'Selector': 'requestAuthorization',
            'Arguments': 'void (^)(SFSpeechRecognizerAuthorizationStatus status)',
            'RET': None,
            'Description': '要求用户允许您的应用执行语音识别。'
        }, {
            'Receiver': 'AVAudioSession',
            'Selector': 'requestRecordPermission:',
            'Arguments': 'PermissionBlock',
            'RET': None,
            'Description': '请求用户允许录音。'
        }, {
            'Receiver': 'AVCaptureDevice',
            'Selector': 'requestAccessForMediaType:completionHandler:',
            'Arguments': 'AVMediaType,BOOL',
            'RET': None,
            'Description': '如果需要，请求用户允许记录指定的媒体类型。microphone and camera'
        }
    ],
    'Contacts': [
        {
            'Receiver': 'ABAddressBook',
            'Selector': 'initWithAddressBook:',
            'Arguments': 'ABAddressBook',
            'RET': 'id',
            'Description': 'Initializes a record using the given address book.'
        }, {
            'Receiver': 'ABAddressBook',
            'Selector': 'sharedAddressBook',
            'Arguments': None,
            'RET': 'ABAddressBook',
            'Description': 'Returns the unique shared instance of ABAddressBook, or nil if the Address Book database can’t be initialized.'
        }, {
            'Receiver': 'ABPerson',
            'Selector': 'initWithVCardRepresentation:',
            'Arguments': 'NSData',
            'RET': 'id',
            'Description': 'ABPerson使用给定数据初始化的实例.'
        }, {
            'Receiver': 'CNContactStore',
            'Selector': 'requestAccessForEntityType:completionHandler:',
            'Arguments': 'CNEntityType,block',  # (void (^)(BOOL granted, NSError *error))
            'RET': None,
            'Description': '用户可以基于每个应用程序授予或拒绝访问联系人数据。通过调用方法请求访问联系人数据。.'
        }
    ],
    'photo': [

        {
            'Receiver': 'PHPhotoLibrary',
            'Selector': 'requestAuthorization:',
            'Arguments': 'block',
            'RET': None,
            'Description': '要求变更库中的内容，照片会自动并异步提示用户请求授权。或者，您可以调用此方法在您选择的时间提示用户'
        }, {
            'Receiver': 'PHPhotoLibrary',
            'Selector': 'sharedPhotoLibrary',
            'Arguments': None,
            'RET': 'PHPhotoLibrary',
            'Description': '您可以从任何线程使用共享照片库对象。'
        }, {
            'Receiver': 'PHPhotoLibrary',
            'Selector': 'registerChangeObserver:',
            'Arguments': 'id<PHPhotoLibraryChangeObserver>',
            'RET': None,
            'Description': '注册对象以在照片库中的对象发生更改时接收消息'
        }, {
            'Receiver': 'AVCapturePhotoSettings',
            'Selector': 'photoSettings',
            'Arguments': None,
            'RET': 'id',
            'Description': '使用默认设置创建照片设置对象。'
        }, {
            'Receiver': 'AVCapturePhotoOutput',
            'Selector': 'init',
            'Arguments': None,
            'RET': 'id',
            'Description': '初始化新的照片捕获输出对象。'
        }, {
            'Receiver': 'AVCapturePhotoOutput',
            'Selector': 'capturePhotoWithSettings:delegate:',
            'Arguments': 'AVCapturePhotoSettings,id<AVCapturePhotoCaptureDelegate>',
            'RET': None,
            'Description': '使用指定的设置启动照片捕获。'
        }

    ],
    'Device': [
        {
            'Receiver': 'UIDevice',
            'Selector': 'identifierForVendor',
            'Arguments': None,
            'RET': 'NSUUID',
            'Description': '一个字母数字字符串，用于唯一标识应用程序供应商的设备。'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'name',
            'Arguments': None,
            'RET': 'NSString',
            'Description': '标识设备的名称'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'systemName',
            'Arguments': None,
            'RET': 'NSString',
            'Description': '在接收器表示的设备上运行的操作系统的名称'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'systemVersion',
            'Arguments': None,
            'RET': 'NSString',
            'Description': '当前版本的操作系统'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'model',
            'Arguments': None,
            'RET': 'NSString',
            'Description': '设备的型号'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'currentDevice',
            'Arguments': None,
            'RET': 'UIDevice',
            'Description': '返回表示当前设备的对象'
        }, {
            'Receiver': 'UIDevice',
            'Selector': 'batteryLevel',
            'Arguments': None,
            'RET': 'float',
            'Description': '设备的电池电量'
        }
    ],
    'Email': [
        {
            'Receiver': 'MFMailComposeViewController',
            'Selector': 'canSendMail',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '返回一个布尔值，指示当前设备是否能够发送电子邮件'
        }, {
            'Receiver': 'MFMailComposeViewController',
            'Selector': 'setToRecipients:',
            'Arguments': 'NSArray',  # (NSArray<NSString *> *)
            'RET': None,
            'Description': '设置要包含在电子邮件“收件人”字段中的初始收件人'
        }
    ],
    'Message': [
        {
            'Receiver': 'MSMessagesAppViewController',
            'Selector': 'didReceiveMessage:conversation:',
            'Arguments': 'MSMessage,MSConversation',
            'RET': None,
            'Description': '在iMessage应用程序收到新消息对象时调用。'
        }, {
            'Receiver': 'MSMessagesAppViewController',
            'Selector': 'didStartSendingMessage:conversation:',
            'Arguments': 'MSMessage,MSConversation',
            'RET': None,
            'Description': '用户发送消息对象时调用'
        }, {
            'Receiver': 'MSConversation',
            'Selector': 'insertMessage:completionHandler:',
            'Arguments': 'MSMessage,block',
            'RET': None,
            'Description': '将消息对象插入消息应用程序的输入字段。'
        }, {
            'Receiver': 'MSConversation',
            'Selector': 'sendText:completionHandler:',
            'Arguments': 'NSString,block',
            'RET': None,
            'Description': '发送短信。'
        }, {
            'Receiver': 'MFMessageComposeViewController',
            'Selector': 'canSendText',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '返回一个布尔值，指示当前设备是否能够发送文本消息。。'
        }, {
            'Receiver': 'MFMessageComposeViewController',
            'Selector': 'canSendAttachments',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '指示消息是否可以包含附件。。'
        }, {
            'Receiver': 'MFMessageComposeViewController',
            'Selector': 'canSendSubject',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '根据用户在“设置”中的配置，指示消息是否可以包含主题行。。'
        },
    ],
    'Homekit': [
        {
            'Receiver': 'HMHomeManager',
            'Selector': 'addHomeWithName:completionHandler:',
            'Arguments': 'NSString,block',
            'RET': None,
            'Description': '添加新家'
        }, {
            'Receiver': 'HMHome',
            'Selector': 'addZoneWithName:completionHandler:',
            'Arguments': 'NSString,block',
            'RET': None,
            'Description': '为家添加新区域'
        }, {
            'Receiver': 'HMHome',
            'Selector': 'addRoomWithName:completionHandler:',
            'Arguments': 'NSString,block',
            'RET': None,
            'Description': '为家添加新房间'
        }
    ],
    'sports&geo': [
        {
            'Receiver': 'CMMotionManager',
            'Selector': 'startDeviceMotionUpdates',
            'Arguments': None,
            'RET': None,
            'Description': '您可以通过该属性获取最新的设备运动数据。当您不再希望应用程序处理设备动态更新时，您必须致电。此方法使用返回的参考帧进行设备运动更新'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'startWatchAppWithWorkoutConfiguration:completion:',
            'Arguments': 'HKWorkoutConfiguration,block',
            'RET': None,
            'Description': '启动或唤醒Watch应用程序以创建新的锻炼课程。'
        }, {
            'Receiver': 'HKHealthStore',
            'Selector': 'startWorkoutSession:',
            'Arguments': 'HKWorkoutSession',
            'RET': None,
            'Description': '开始当前应用的锻炼课程'
        }, {
            'Receiver': 'CMMotionManager',
            'Selector': 'startDeviceMotionUpdatesUsingReferenceFrame:',
            'Arguments': 'CMAttitudeReferenceFrame',
            'RET': None,
            'Description': '在操作队列上启动设备动作更新，并使用指定的参考框架和块处理程序。'
        }, {
            'Receiver': 'CMMotionActivityManager',
            'Selector': 'isActivityAvailable',
            'Arguments': None,
            'RET': 'Bool',
            'Description': '返回一个布尔值，指示当前设备上的运动数据是否可用。'
        }, {
            'Receiver': 'CMSensorRecorder',
            'Selector': 'isAccelerometerRecordingAvailable',
            'Arguments': None,
            'RET': 'Bool',
            'Description': '返回一个布尔值，指示当前设备是否支持加速度计记录。'
        }, {
            'Receiver': 'CMMotionActivityManager',
            'Selector': 'startActivityUpdatesToQueue:withHandler:',
            'Arguments': 'NSOperationQueue,CMMotionActivityHandler',
            'RET': None,
            'Description': '开始向您的应用发送当前动态数据更新。。'
        }, {
            'Receiver': 'CMMovementDisorderManager',
            'Selector': 'monitorKinesiasForDuration:',
            'Arguments': 'NSTimeInterval',
            'RET': None,
            'Description': '在指定的时间间隔内计算并存储震颤和运动障碍症状结果。。'
        }, {
            'Receiver': 'CMMovementDisorderManager',
            'Selector': 'monitorKinesiasExpirationDate',
            'Arguments': None,
            'RET': 'NSDate',
            'Description': '返回最近监视时段的到期日期。。。'
        }, {
            'Receiver': 'CMMotionActivityManager',
            'Selector': 'queryActivityStartingFromDate:toDate:toQueue:withHandler:',
            'Arguments': 'NSDate,NSDate,NSOperationQueue,CMMotionActivityQueryHandler',
            'RET': None,
            'Description': '收集并返回指定时间段的历史运动数据。。'
        },
    ],
    'Icloud': [
        {
            'Receiver': 'CKRecord',
            'Selector': 'initWithRecordType:',
            'Arguments': 'CKRecordType',
            'RET': 'id',
            'Description': '初始化的记录对象或nil无法创建记录。icloud'
        }, {
            'Receiver': 'CKModifyRecordsOperation',
            'Selector': 'init',
            'Arguments': None,
            'RET': 'id',
            'Description': '使用此初始化程序时，应该在将操作移交给要执行的数据库之前填充和/或属性。。icloud'
        }, {
            'Receiver': 'CKModifyRecordsOperation',
            'Selector': 'initWithRecordsToSave:recordIDsToDelete:',
            'Arguments': 'NSArray,NSArray',  # NSArray<CKRecord *> *,NSArray<CKRecordID *> *
            'RET': 'id',
            'Description': '您要保存或删除的记录必须全部驻留在同一数据库中，您可以在配置操作对象时指定该数据库。保存不在当前数据库中的记录会在数据库中创建它。尝试删除当前数据库中不存在的记录会返回该记录的错误。icloud'
        }, {
            'Receiver': 'CKRecord',
            'Selector': 'initWithRecordType:zoneID:',
            'Arguments': 'CKRecordType,CKRecordZoneID',
            'RET': 'id',
            'Description': '使用此方法初始化指定记录区域中的新记录对象。icloud'
        }, {
            'Receiver': 'CKRecord',
            'Selector': 'initWithRecordType:zoneID:',
            'Arguments': 'CKRecordType,CKRecordID',
            'RET': 'id',
            'Description': '初始化的记录对象或nil无法创建记录。icloud'
        }
    ],
    'Geo': [
        {
            'Receiver': 'UNLocationNotificationTrigger',
            'Selector': 'triggerWithRegion:repeats:',
            'Arguments': '(CLRegion *)region,(BOOL)repeats',
            'RET': 'id',
            'Description': '具有指定区域的新位置触发器对象。'
        }, {
            'Receiver': 'MKMapItem',
            'Selector': 'mapItemForCurrentLocation',
            'Arguments': None,
            'RET': 'MKMapItem',
            'Description': '创建并返回表示设备当前位置的单例映射项对象。'
        }, {
            'Receiver': 'MKMapItem',
            'Selector': 'initWithPlacemark:',
            'Arguments': 'MKPlacemark',
            'RET': 'id',
            'Description': '与所需地图位置对应的地标对象。此参数不得为nil。'
        }, {
            'Receiver': 'CLPlacemark',
            'Selector': 'initWithPlacemark:',
            'Arguments': 'CLPlacemark',
            'RET': 'id',
            'Description': '从另一个地标对象初始化并返回一个地标对象。'
        }, {
            'Receiver': 'INSpatialEventTrigger',
            'Selector': 'initWithPlacemark:event:',
            'Arguments': 'CLPlacemark,INSpatialEvent',
            'RET': 'id',
            'Description': '使用指定的基于位置的信息初始化事件触发器。。'
        }, {
            'Receiver': 'MKPlacemark',
            'Selector': 'initWithCoordinate:',
            'Arguments': 'CLLocationCoordinate2D',
            'RET': 'id',
            'Description': '使用指定的坐标初始化并返回地标对象。。'
        }, {
            'Receiver': 'MKReverseGeocoder',
            'Selector': 'initWithCoordinate:',
            'Arguments': 'CLLocationCoordinate2D',
            'RET': 'id',
            'Description': '使用指定的坐标值初始化反向地理编码器。。。'
        }, {
            'Receiver': 'CLGeocoder',
            'Selector': 'reverseGeocodeLocation:completionHandler:',
            'Arguments': 'CLLocation,CLGeocodeCompletionHandler',
            'RET': None,
            'Description': '提交指定位置的反向地理编码请求。。。'
        }, {
            'Receiver': 'CPMapTemplate',
            'Selector': 'startNavigationSessionForTrip:',
            'Arguments': 'CPTrip',
            'RET': 'CPNavigationSession',
            'Description': '保持对导航会话的引用以执行指导更新'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'locationServicesEnabled',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': 'YES if location services are enabled; NO if they are not.'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'deferredLocationUpdatesAvailable',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': 'YES if the device supports deferred location updates or NO if it does not.'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'authorizationStatus',
            'Arguments': None,
            'RET': 'CLAuthorizationStatus',
            'Description': '给定应用程序的授权状态由系统管理，并由多个因素决定。必须明确授权用户使用用户的位置服务，并且当前必须为系统启用位置服务。当您的应用首次尝试使用位置服务时，会自动显示用户授权请求。.'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'significantLocationChangeMonitoringAvailable',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': 'YES if location change monitoring is available; NO if it is not..'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'isMonitoringAvailableForClass:',
            'Arguments': 'Class',
            'RET': 'BOOL',
            'Description': '告诉您是否可以使用区域监控来检测进入或退出地理区域或iBeacon区域。'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'headingAvailable',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '告诉您是否可以使用区域监控来检测进入或退出地理区域或iBeacon区域。'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'isRangingAvailable',
            'Arguments': None,
            'RET': 'BOOL',
            'Description': '返回一个布尔值，指示设备是否支持蓝牙信标范围'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'requestWhenInUseAuthorization',
            'Arguments': None,
            'RET': None,
            'Description': '请求在应用程序位于前台时使用位置服务的权限'
        }, {
            'Receiver': 'CLLocationManager',
            'Selector': 'startUpdatingLocation',
            'Arguments': None,
            'RET': None,
            'Description': '开始生成报告用户当前位置的更新'
        }, {
            'Receiver': 'MCNearbyServiceBrowser',
            'Selector': 'initWithPeer:serviceType:',
            'Arguments': 'MCPeerID,NSString',
            'RET': 'id',
            'Description': '初始化附近的服务浏览器对象'
        }
    ]
}

for data_type, rules in SEC_RULES.items():
    print '/\\' * 10
    print data_type
    print '/\\' * 10
    for rule in rules:
        for key, info in rule.items():
            print key, info
