#ifdef WIN32
//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//


//
// MessageId: MSG
//
// MessageText:
//
//  %1
//
#define MSG                              ((WORD)0x00000001L)

//
// MessageId: EVMSG_INSTALLED
//
// MessageText:
//
//  The %1 service was installed.
//
#define EVMSG_INSTALLED                  ((WORD)0x00000002L)

//
// MessageId: EVMSG_REMOVED
//
// MessageText:
//
//  The %1 service was removed.
//
#define EVMSG_REMOVED                    ((WORD)0x00000003L)

//
// MessageId: EVMSG_NOTREMOVED
//
// MessageText:
//
//  The %1 service could not be removed.
//
#define EVMSG_NOTREMOVED                 ((WORD)0x00000004L)

//
// MessageId: EVMSG_CTRLHANDLERNOTINSTALLED
//
// MessageText:
//
//  The control handler could not be installed.
//
#define EVMSG_CTRLHANDLERNOTINSTALLED    ((WORD)0x00000005L)

//
// MessageId: EVMSG_FAILEDINIT
//
// MessageText:
//
//  The initialization process failed.
//
#define EVMSG_FAILEDINIT                 ((WORD)0x00000006L)

//
// MessageId: EVMSG_STARTED
//
// MessageText:
//
//  The service was started.
//
#define EVMSG_STARTED                    ((WORD)0x00000007L)

//
// MessageId: EVMSG_BADREQUEST
//
// MessageText:
//
//  The service received an unsupported request.
//
#define EVMSG_BADREQUEST                 ((WORD)0x00000008L)

//
// MessageId: EVMSG_DEBUG
//
// MessageText:
//
//  Debug: %1
//
#define EVMSG_DEBUG                      ((WORD)0x00000009L)

//
// MessageId: EVMSG_STOPPED
//
// MessageText:
//
//  The service was stopped.
//
#define EVMSG_STOPPED                    ((WORD)0x00000010L)

#endif
