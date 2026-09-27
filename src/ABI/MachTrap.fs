(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.ABI

open B2R2

/// Represents macOS (Darwin/XNU) Mach traps: the entry points into the Mach
/// half of the kernel, as against the BSD system calls MacosSyscall names.
/// They are a namespace of their own -- Mach trap 28 and BSD call 28 are
/// different calls -- and they report failure differently too, returning a
/// kern_return_t in the result register with no errno and no carry flag. The
/// enum values are arbitrary indices; use MachTrap.toNumber for the number a
/// given ISA passes.
type MachTrap =
  | ClockSleepTrap = 0
  | DebugControlPortForPid = 1
  | ExclavesCtlTrap = 2
  | HostCreateMachVoucherTrap = 3
  | HostSelfTrap = 4
  | KernelrpcMachPortAllocateTrap = 5
  | KernelrpcMachPortConstructTrap = 6
  | KernelrpcMachPortDeallocateTrap = 7
  | KernelrpcMachPortDestructTrap = 8
  | KernelrpcMachPortExtractMemberTrap = 9
  | KernelrpcMachPortGetAttributesTrap = 10
  | KernelrpcMachPortGuardTrap = 11
  | KernelrpcMachPortInsertMemberTrap = 12
  | KernelrpcMachPortInsertRightTrap = 13
  | KernelrpcMachPortModRefsTrap = 14
  | KernelrpcMachPortMoveMemberTrap = 15
  | KernelrpcMachPortRequestNotificationTrap = 16
  | KernelrpcMachPortTypeTrap = 17
  | KernelrpcMachPortUnguardTrap = 18
  | KernelrpcMachVmAllocateTrap = 19
  | KernelrpcMachVmDeallocateTrap = 20
  | KernelrpcMachVmMapTrap = 21
  | KernelrpcMachVmProtectTrap = 22
  | KernelrpcMachVmPurgableControlTrap = 23
  | MachGenerateActivityId = 24
  | MachMsg2Trap = 25
  | MachMsgOverwriteTrap = 26
  | MachMsgTrap = 27
  | MachReplyPort = 28
  | MachTimebaseInfoTrap = 29
  | MachVmReclaimUpdateKernelAccountingTrap = 30
  | MachVoucherExtractAttrRecipeTrap = 31
  | MachWaitUntil = 32
  | MacxBackingStoreRecovery = 33
  | MacxBackingStoreSuspend = 34
  | MacxSwapoff = 35
  | MacxSwapon = 36
  | MacxTriggers = 37
  | MkTimerArm = 38
  | MkTimerArmLeeway = 39
  | MkTimerCancel = 40
  | MkTimerCreate = 41
  | MkTimerDestroy = 42
  | PidForTask = 43
  | SemaphoreSignalAllTrap = 44
  | SemaphoreSignalThreadTrap = 45
  | SemaphoreSignalTrap = 46
  | SemaphoreTimedwaitSignalTrap = 47
  | SemaphoreTimedwaitTrap = 48
  | SemaphoreWaitSignalTrap = 49
  | SemaphoreWaitTrap = 50
  | Swtch = 51
  | SwtchPri = 52
  | SyscallThreadSwitch = 53
  | TaskDyldProcessInfoNotifyGet = 54
  | TaskForPid = 55
  | TaskNameForPid = 56
  | TaskSelfTrap = 57
  | ThreadGetSpecialReplyPort = 58
  | ThreadSelfTrap = 59

/// Provides functions to convert Mach trap numbers to their corresponding trap
/// types and vice versa. The trap numbers are the same on x86_64 and arm64;
/// only the encoding in the number register differs.
[<RequireQualifiedAccess>]
module MachTrap =
  /// The trap's own number, as <kern/syscall_sw.c> tabulates it. The table in
  /// <mach/syscall_sw.h> writes each one negated, which is how arm64 passes
  /// it; the positive value is what the table is indexed by.
  let private getTrapNumber = function
    | MachTrap.ClockSleepTrap -> 62
    | MachTrap.DebugControlPortForPid -> 96
    | MachTrap.ExclavesCtlTrap -> 88
    | MachTrap.HostCreateMachVoucherTrap -> 70
    | MachTrap.HostSelfTrap -> 29
    | MachTrap.KernelrpcMachPortAllocateTrap -> 16
    | MachTrap.KernelrpcMachPortConstructTrap -> 24
    | MachTrap.KernelrpcMachPortDeallocateTrap -> 18
    | MachTrap.KernelrpcMachPortDestructTrap -> 25
    | MachTrap.KernelrpcMachPortExtractMemberTrap -> 23
    | MachTrap.KernelrpcMachPortGetAttributesTrap -> 40
    | MachTrap.KernelrpcMachPortGuardTrap -> 41
    | MachTrap.KernelrpcMachPortInsertMemberTrap -> 22
    | MachTrap.KernelrpcMachPortInsertRightTrap -> 21
    | MachTrap.KernelrpcMachPortModRefsTrap -> 19
    | MachTrap.KernelrpcMachPortMoveMemberTrap -> 20
    | MachTrap.KernelrpcMachPortRequestNotificationTrap -> 77
    | MachTrap.KernelrpcMachPortTypeTrap -> 76
    | MachTrap.KernelrpcMachPortUnguardTrap -> 42
    | MachTrap.KernelrpcMachVmAllocateTrap -> 10
    | MachTrap.KernelrpcMachVmDeallocateTrap -> 12
    | MachTrap.KernelrpcMachVmMapTrap -> 15
    | MachTrap.KernelrpcMachVmProtectTrap -> 14
    | MachTrap.KernelrpcMachVmPurgableControlTrap -> 11
    | MachTrap.MachGenerateActivityId -> 43
    | MachTrap.MachMsg2Trap -> 47
    | MachTrap.MachMsgOverwriteTrap -> 32
    | MachTrap.MachMsgTrap -> 31
    | MachTrap.MachReplyPort -> 26
    | MachTrap.MachTimebaseInfoTrap -> 89
    | MachTrap.MachVmReclaimUpdateKernelAccountingTrap -> 63
    | MachTrap.MachVoucherExtractAttrRecipeTrap -> 72
    | MachTrap.MachWaitUntil -> 90
    | MachTrap.MacxBackingStoreRecovery -> 53
    | MachTrap.MacxBackingStoreSuspend -> 52
    | MachTrap.MacxSwapoff -> 49
    | MachTrap.MacxSwapon -> 48
    | MachTrap.MacxTriggers -> 51
    | MachTrap.MkTimerArm -> 93
    | MachTrap.MkTimerArmLeeway -> 95
    | MachTrap.MkTimerCancel -> 94
    | MachTrap.MkTimerCreate -> 91
    | MachTrap.MkTimerDestroy -> 92
    | MachTrap.PidForTask -> 46
    | MachTrap.SemaphoreSignalAllTrap -> 34
    | MachTrap.SemaphoreSignalThreadTrap -> 35
    | MachTrap.SemaphoreSignalTrap -> 33
    | MachTrap.SemaphoreTimedwaitSignalTrap -> 39
    | MachTrap.SemaphoreTimedwaitTrap -> 38
    | MachTrap.SemaphoreWaitSignalTrap -> 37
    | MachTrap.SemaphoreWaitTrap -> 36
    | MachTrap.Swtch -> 60
    | MachTrap.SwtchPri -> 59
    | MachTrap.SyscallThreadSwitch -> 61
    | MachTrap.TaskDyldProcessInfoNotifyGet -> 13
    | MachTrap.TaskForPid -> 45
    | MachTrap.TaskNameForPid -> 44
    | MachTrap.TaskSelfTrap -> 28
    | MachTrap.ThreadGetSpecialReplyPort -> 50
    | MachTrap.ThreadSelfTrap -> 27
    | _ -> raise UnhandledSyscallException

  (* On x86_64 the Mach syscall class (SYSCALL_CLASS_MACH = 1) rides in the
     high bits of the number register, so RAX holds 0x1000000 ||| n. On arm64
     the number goes in x16 negated, which is how a Mach trap is told apart
     from a BSD call there. *)
  [<CompiledName "ToNumber">]
  let toNumber isa trap =
    match isa with
    | X64 -> 0x1000000 ||| getTrapNumber trap
    | AArch64 -> -(getTrapNumber trap)
    | _ -> raise UnhandledSyscallException

  let private getTrap = function
    | 10 -> MachTrap.KernelrpcMachVmAllocateTrap
    | 11 -> MachTrap.KernelrpcMachVmPurgableControlTrap
    | 12 -> MachTrap.KernelrpcMachVmDeallocateTrap
    | 13 -> MachTrap.TaskDyldProcessInfoNotifyGet
    | 14 -> MachTrap.KernelrpcMachVmProtectTrap
    | 15 -> MachTrap.KernelrpcMachVmMapTrap
    | 16 -> MachTrap.KernelrpcMachPortAllocateTrap
    | 18 -> MachTrap.KernelrpcMachPortDeallocateTrap
    | 19 -> MachTrap.KernelrpcMachPortModRefsTrap
    | 20 -> MachTrap.KernelrpcMachPortMoveMemberTrap
    | 21 -> MachTrap.KernelrpcMachPortInsertRightTrap
    | 22 -> MachTrap.KernelrpcMachPortInsertMemberTrap
    | 23 -> MachTrap.KernelrpcMachPortExtractMemberTrap
    | 24 -> MachTrap.KernelrpcMachPortConstructTrap
    | 25 -> MachTrap.KernelrpcMachPortDestructTrap
    | 26 -> MachTrap.MachReplyPort
    | 27 -> MachTrap.ThreadSelfTrap
    | 28 -> MachTrap.TaskSelfTrap
    | 29 -> MachTrap.HostSelfTrap
    | 31 -> MachTrap.MachMsgTrap
    | 32 -> MachTrap.MachMsgOverwriteTrap
    | 33 -> MachTrap.SemaphoreSignalTrap
    | 34 -> MachTrap.SemaphoreSignalAllTrap
    | 35 -> MachTrap.SemaphoreSignalThreadTrap
    | 36 -> MachTrap.SemaphoreWaitTrap
    | 37 -> MachTrap.SemaphoreWaitSignalTrap
    | 38 -> MachTrap.SemaphoreTimedwaitTrap
    | 39 -> MachTrap.SemaphoreTimedwaitSignalTrap
    | 40 -> MachTrap.KernelrpcMachPortGetAttributesTrap
    | 41 -> MachTrap.KernelrpcMachPortGuardTrap
    | 42 -> MachTrap.KernelrpcMachPortUnguardTrap
    | 43 -> MachTrap.MachGenerateActivityId
    | 44 -> MachTrap.TaskNameForPid
    | 45 -> MachTrap.TaskForPid
    | 46 -> MachTrap.PidForTask
    | 47 -> MachTrap.MachMsg2Trap
    | 48 -> MachTrap.MacxSwapon
    | 49 -> MachTrap.MacxSwapoff
    | 50 -> MachTrap.ThreadGetSpecialReplyPort
    | 51 -> MachTrap.MacxTriggers
    | 52 -> MachTrap.MacxBackingStoreSuspend
    | 53 -> MachTrap.MacxBackingStoreRecovery
    | 59 -> MachTrap.SwtchPri
    | 60 -> MachTrap.Swtch
    | 61 -> MachTrap.SyscallThreadSwitch
    | 62 -> MachTrap.ClockSleepTrap
    | 63 -> MachTrap.MachVmReclaimUpdateKernelAccountingTrap
    | 70 -> MachTrap.HostCreateMachVoucherTrap
    | 72 -> MachTrap.MachVoucherExtractAttrRecipeTrap
    | 76 -> MachTrap.KernelrpcMachPortTypeTrap
    | 77 -> MachTrap.KernelrpcMachPortRequestNotificationTrap
    | 88 -> MachTrap.ExclavesCtlTrap
    | 89 -> MachTrap.MachTimebaseInfoTrap
    | 90 -> MachTrap.MachWaitUntil
    | 91 -> MachTrap.MkTimerCreate
    | 92 -> MachTrap.MkTimerDestroy
    | 93 -> MachTrap.MkTimerArm
    | 94 -> MachTrap.MkTimerCancel
    | 95 -> MachTrap.MkTimerArmLeeway
    | 96 -> MachTrap.DebugControlPortForPid
    | _ -> raise UnhandledSyscallException

  [<CompiledName "OfNumber">]
  let ofNumber arch num =
    match arch with
    | X64 -> getTrap (num &&& 0xffffff)
    | AArch64 -> getTrap (-num)
    | _ -> raise UnhandledSyscallException

  /// Converts a MachTrap to a string.
  [<CompiledName "ToString">]
  let toString = function
    | MachTrap.ClockSleepTrap ->
      "clock_sleep_trap"
    | MachTrap.DebugControlPortForPid ->
      "debug_control_port_for_pid"
    | MachTrap.ExclavesCtlTrap ->
      "_exclaves_ctl_trap"
    | MachTrap.HostCreateMachVoucherTrap ->
      "host_create_mach_voucher_trap"
    | MachTrap.HostSelfTrap ->
      "host_self_trap"
    | MachTrap.KernelrpcMachPortAllocateTrap ->
      "_kernelrpc_mach_port_allocate_trap"
    | MachTrap.KernelrpcMachPortConstructTrap ->
      "_kernelrpc_mach_port_construct_trap"
    | MachTrap.KernelrpcMachPortDeallocateTrap ->
      "_kernelrpc_mach_port_deallocate_trap"
    | MachTrap.KernelrpcMachPortDestructTrap ->
      "_kernelrpc_mach_port_destruct_trap"
    | MachTrap.KernelrpcMachPortExtractMemberTrap ->
      "_kernelrpc_mach_port_extract_member_trap"
    | MachTrap.KernelrpcMachPortGetAttributesTrap ->
      "_kernelrpc_mach_port_get_attributes_trap"
    | MachTrap.KernelrpcMachPortGuardTrap ->
      "_kernelrpc_mach_port_guard_trap"
    | MachTrap.KernelrpcMachPortInsertMemberTrap ->
      "_kernelrpc_mach_port_insert_member_trap"
    | MachTrap.KernelrpcMachPortInsertRightTrap ->
      "_kernelrpc_mach_port_insert_right_trap"
    | MachTrap.KernelrpcMachPortModRefsTrap ->
      "_kernelrpc_mach_port_mod_refs_trap"
    | MachTrap.KernelrpcMachPortMoveMemberTrap ->
      "_kernelrpc_mach_port_move_member_trap"
    | MachTrap.KernelrpcMachPortRequestNotificationTrap ->
      "_kernelrpc_mach_port_request_notification_trap"
    | MachTrap.KernelrpcMachPortTypeTrap ->
      "_kernelrpc_mach_port_type_trap"
    | MachTrap.KernelrpcMachPortUnguardTrap ->
      "_kernelrpc_mach_port_unguard_trap"
    | MachTrap.KernelrpcMachVmAllocateTrap ->
      "_kernelrpc_mach_vm_allocate_trap"
    | MachTrap.KernelrpcMachVmDeallocateTrap ->
      "_kernelrpc_mach_vm_deallocate_trap"
    | MachTrap.KernelrpcMachVmMapTrap ->
      "_kernelrpc_mach_vm_map_trap"
    | MachTrap.KernelrpcMachVmProtectTrap ->
      "_kernelrpc_mach_vm_protect_trap"
    | MachTrap.KernelrpcMachVmPurgableControlTrap ->
      "_kernelrpc_mach_vm_purgable_control_trap"
    | MachTrap.MachGenerateActivityId ->
      "mach_generate_activity_id"
    | MachTrap.MachMsg2Trap ->
      "mach_msg2_trap"
    | MachTrap.MachMsgOverwriteTrap ->
      "mach_msg_overwrite_trap"
    | MachTrap.MachMsgTrap ->
      "mach_msg_trap"
    | MachTrap.MachReplyPort ->
      "mach_reply_port"
    | MachTrap.MachTimebaseInfoTrap ->
      "mach_timebase_info_trap"
    | MachTrap.MachVmReclaimUpdateKernelAccountingTrap ->
      "mach_vm_reclaim_update_kernel_accounting_trap"
    | MachTrap.MachVoucherExtractAttrRecipeTrap ->
      "mach_voucher_extract_attr_recipe_trap"
    | MachTrap.MachWaitUntil ->
      "mach_wait_until"
    | MachTrap.MacxBackingStoreRecovery ->
      "macx_backing_store_recovery"
    | MachTrap.MacxBackingStoreSuspend ->
      "macx_backing_store_suspend"
    | MachTrap.MacxSwapoff ->
      "macx_swapoff"
    | MachTrap.MacxSwapon ->
      "macx_swapon"
    | MachTrap.MacxTriggers ->
      "macx_triggers"
    | MachTrap.MkTimerArm ->
      "mk_timer_arm"
    | MachTrap.MkTimerArmLeeway ->
      "mk_timer_arm_leeway"
    | MachTrap.MkTimerCancel ->
      "mk_timer_cancel"
    | MachTrap.MkTimerCreate ->
      "mk_timer_create"
    | MachTrap.MkTimerDestroy ->
      "mk_timer_destroy"
    | MachTrap.PidForTask ->
      "pid_for_task"
    | MachTrap.SemaphoreSignalAllTrap ->
      "semaphore_signal_all_trap"
    | MachTrap.SemaphoreSignalThreadTrap ->
      "semaphore_signal_thread_trap"
    | MachTrap.SemaphoreSignalTrap ->
      "semaphore_signal_trap"
    | MachTrap.SemaphoreTimedwaitSignalTrap ->
      "semaphore_timedwait_signal_trap"
    | MachTrap.SemaphoreTimedwaitTrap ->
      "semaphore_timedwait_trap"
    | MachTrap.SemaphoreWaitSignalTrap ->
      "semaphore_wait_signal_trap"
    | MachTrap.SemaphoreWaitTrap ->
      "semaphore_wait_trap"
    | MachTrap.Swtch ->
      "swtch"
    | MachTrap.SwtchPri ->
      "swtch_pri"
    | MachTrap.SyscallThreadSwitch ->
      "syscall_thread_switch"
    | MachTrap.TaskDyldProcessInfoNotifyGet ->
      "task_dyld_process_info_notify_get"
    | MachTrap.TaskForPid ->
      "task_for_pid"
    | MachTrap.TaskNameForPid ->
      "task_name_for_pid"
    | MachTrap.TaskSelfTrap ->
      "task_self_trap"
    | MachTrap.ThreadGetSpecialReplyPort ->
      "thread_get_special_reply_port"
    | MachTrap.ThreadSelfTrap ->
      "thread_self_trap"
    | _ ->
      raise UnhandledSyscallException
