/* packet-PROTOABBREV.c
 * Routines for PROTONAME dissection
 * Copyright 201x, YOUR_NAME <YOUR_EMAIL_ADDRESS>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/wmem/wmem.h>
#include <epan/wmem/wmem_map.h>  
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */
#include "packet-tcp.h"


#define JDWP_TCP_PORT 8000
#define JDWP_HANDSHAKE_BYTES_COUNT 14
#define REPLY_FLAG 0x80
#define JDWP_HEADER_SIZE 11

#define CLASS_STATUS_VERIFIED_FLAG 0x1
#define CLASS_STATUS_PREPARED_FLAG 0x2
#define CLASS_STATUS_INITIALIZED_FLAG 0x4
#define CLASS_STATUS_ERROR_FLAG 0x8

#define ARRAY 91
#define BYTE 66
#define CHAR 67
#define OBJECT 76
#define FLOAT 70
#define DOUBLE 68
#define INT 73
#define LONG 74
#define SHORT 83
#define VOID 86
#define BOOLEAN 90
#define STRING 115
#define THREAD 116
#define THREAD_GROUP 103
#define CLASS_LOADER 108
#define CLASS_OBJECT 99

#define VM_COMMANDSET 1
#define REFERENCE_TYPE_COMMANDSET 2
#define CLASS_TYPE_COMMANDSET 3
#define ARRAY_TYPE_COMMANDSET 4
#define INTERFACE_TYPE_COMMANDSET 5
#define METHOD_COMMANDSET 6
#define FIELD_COMMANDSET 8
#define OBJECT_REFERENCE_COMMANDSET 9
#define STRING_REFERENCE_COMMANDSET 10
#define THREAD_REFERENCE_COMMANDSET 11
#define THREAD_GROUP_REFERENCE_COMMANDSET 12
#define ARRAY_REFERENCE_COMMANDSET 13
#define CLASSLOADER_REFERENCE_COMMANDSET 14
#define EVENT_REQUEST_COMMANDSET 15
#define STACK_FRAME_COMMANDSET 16
#define CLASS_OBJECT_REFERENCE_COMMANDSET 17
#define EVENT_COMMANDSET 64

#define VERSION_COMMAND 1
#define CLASSES_BY_SIGNATURE_COMMAND 2
#define ALL_CLASSES_COMMAND 3
#define ALL_THREADS_COMMAND 4
#define TOP_LEVEL_THREAD_GROUPS_COMMAND 5
#define DISPOSE_COMMAND 6
#define IDSIZES_COMMAND 7
#define SUSPEND_COMMAND 8
#define RESUME_COMMAND 9
#define EXIT_COMMAND 10
#define CREATE_STRING_COMMAND 11
#define CAPABILITIES_COMMAND 12
#define CLASSPATHS_COMMAND 13
#define DISPOSE_OBJECTS_COMMAND 14
#define HOLD_EVENTS_COMMAND 15
#define RELEASE_EVENTS_COMMAND 16
#define CAPABILITIES_NEW_COMMAND 17
#define REDEFINE_CLASSES_COMMAND 18
#define SET_DEFAULT_STRATUM_COMMAND 19
#define ALL_CLASSES_WITH_GENERIC_COMMAND 20
#define INSTANCE_COUNTS_COMMAND 21

#define SIGNATURE_COMMAND 1
#define CLASSLOADER_COMMAND 2
#define MODIFIERS_COMMAND 3
#define FIELDS_COMMAND 4
#define METHODS_COMMAND 5
#define GET_VALUES_COMMAND 6
#define SOURCE_FILE_COMMAND 7
#define NESTED_TYPES_COMMAND 8
#define STATUS_COMMAND 9
#define INTERFACES_COMMAND 10
#define CLASS_OBJECT_COMMAND 11
#define SOURCE_DEBUG_EXTENSION_COMMAND 12
#define SIGNATURE_WITH_GENERIC_COMMAND 13
#define FIELDS_WITH_GENERIC_COMMAND 14
#define METHODS_WITH_GENERIC_COMMAND 15
#define INSTANCES_COMMAND 16
#define CLASS_FILE_VERSION_COMMAND 17
#define CONSTANT_POOL_COMMAND 18


static const value_string errorcodes[] = {
    { 0, "None" },
    { 10, "Invalid thread" },
    { 11, "Invalid thread group" },
    { 12, "Invalid priority" },
    { 13, "Thread not suspended" },
    { 14, "Thread suspended" },
    { 15, "Thread not alive" },
    { 20, "Invalid object" },
    { 21, "Invalid class" },
    { 22, "Class not prepared" },
    { 23, "Invalid method id" },
    { 24, "Invalid location" },
    { 25, "Invalid field id" },
    { 30, "Invalid frame id" },
    { 31, "No more fames" },
    { 32, "Opaque frame" },
    { 33, "Not current frame" },
    { 34, "Type mismatch" },
    { 35, "Invalid slot" },
    { 40, "Duplicate" },
    { 41, "Not found" },
    { 50, "Invalid monitor" },
    { 51, "Not monitor owner" },
    { 52, "Interrupt" },
    { 60, "Invalid class format" },
    { 61, "Circular class definition" },
    { 62, "Fails verification" },
    { 63, "Add method not implemented" },
    { 64, "Schema change not implemented" },
    { 65, "Invalid type state" },
    { 66, "Hierarchy change not implemented" },
    { 67, "Delete method not implemented" },
    { 68, "Unsupported version" },
    { 69, "Names don't match" },
    { 70, "Class modifiers change not implemented" },
    { 71, "Method modifiers change not implemented" },
    { 99, "Not implemented" },
    { 100, "Null pointer" },
    { 101, "Absent information" },
    { 102, "Invalid event type" },
    { 103, "Illegal argument" },
    { 110, "Out of memory" },
    { 111, "Access denied" },
    { 112, "VM dead" },
    { 113, "Internal" },
    { 115, "Unattached thread" },
    { 500, "Invalid tag" },
    { 502, "Already invoking" },
    { 503, "Invalid index" },
    { 504, "Invalid length" },
    { 506, "Invalid string" },
    { 507, "Invalid class loader" },
    { 508, "Invalid array" },
    { 509, "Transport load" },
    { 510, "Transport init" },
    { 511, "Native method" },
    { 512, "Invalid count" },
    { 0, NULL }
};

static const value_string typetags[] = {
    { 1, "Class" },
    { 2, "Interface" },
    { 3, "Array" },
    { 0, NULL }
};

static const value_string tags[] = {
    { ARRAY, "Array" },
    { BYTE, "Byte" },
    { CHAR, "Char" },
    { OBJECT, "Object" },
    { FLOAT, "Float" },
    { DOUBLE, "Double" },
    { INT, "Int" },
    { LONG, "Long" },
    { SHORT, "Short" },
    { VOID, "Void" },
    { BOOLEAN, "Boolean" },
    { STRING, "String" },
    { THREAD, "Thread" },
    { THREAD_GROUP, "Thread Group" },
    { CLASS_LOADER, "ClassLoader" },
    { CLASS_OBJECT, "Class Object" },
    { 0, NULL }
};

static const value_string commandsets[] = {
    { VM_COMMANDSET, "VirtualMachine" },
    { REFERENCE_TYPE_COMMANDSET, "ReferenceType" },
    { CLASS_TYPE_COMMANDSET, "ClassType" },
    { ARRAY_TYPE_COMMANDSET, "ArrayType" },
    { INTERFACE_TYPE_COMMANDSET, "InterfaceType" },
    { METHOD_COMMANDSET, "Method" },
    { FIELD_COMMANDSET, "Field" },
    { OBJECT_REFERENCE_COMMANDSET, "ObjectReference" },
    { STRING_REFERENCE_COMMANDSET, "StringReference" },
    { THREAD_REFERENCE_COMMANDSET, "ThreadReference" },
    { THREAD_GROUP_REFERENCE_COMMANDSET, "ThreadGroupReference" },
    { ARRAY_REFERENCE_COMMANDSET, "ArrayReference" },
    { CLASSLOADER_REFERENCE_COMMANDSET, "ClassLoaderReference" },
    { EVENT_REQUEST_COMMANDSET, "EventRequest" },
    { STACK_FRAME_COMMANDSET, "StackFrame" },
    { CLASS_OBJECT_REFERENCE_COMMANDSET, "ClassObjectReference" },
    { EVENT_COMMANDSET, "Event" },
    { 0, NULL }
};

static const value_string virtualmachine_commands[] = {
    { VERSION_COMMAND, "Version" },
    { CLASSES_BY_SIGNATURE_COMMAND, "ClassesBySignature" },
    { ALL_CLASSES_COMMAND, "AllClasses" },
    { ALL_THREADS_COMMAND, "AllThreads" },
    { TOP_LEVEL_THREAD_GROUPS_COMMAND, "TopLevelThreadGroups" },
    { DISPOSE_COMMAND, "Dispose" },
    { IDSIZES_COMMAND, "IDSizes" },
    { SUSPEND_COMMAND, "Suspend" },
    { RESUME_COMMAND, "Resume" },
    { EXIT_COMMAND, "Exit" },
    { CREATE_STRING_COMMAND, "CreateString" },
    { CAPABILITIES_COMMAND, "Capabilities" },
    { CLASSPATHS_COMMAND, "ClassPaths" },
    { DISPOSE_OBJECTS_COMMAND, "DisposeObjects" },
    { HOLD_EVENTS_COMMAND, "HoldEvents" },
    { RELEASE_EVENTS_COMMAND, "ReleaseEvents" },
    { CAPABILITIES_NEW_COMMAND, "CapabilitiesNew" },
    { REDEFINE_CLASSES_COMMAND, "RedefineClasses" },
    { SET_DEFAULT_STRATUM_COMMAND, "SetDefaultStratum" },
    { ALL_CLASSES_WITH_GENERIC_COMMAND, "AllClassesWithGeneric" },
    { INSTANCE_COUNTS_COMMAND, "InstanceCounts" },
    { 0, NULL }
};

static const value_string referencetype_commands[] = {
    { SIGNATURE_COMMAND, "Signature" },
    { CLASSLOADER_COMMAND, "ClassLoader" },
    { MODIFIERS_COMMAND, "Modifiers" },
    { FIELDS_COMMAND, "Fields" },
    { METHODS_COMMAND, "Methods" },
    { GET_VALUES_COMMAND, "GetValues" },
    { SOURCE_FILE_COMMAND, "SourceFile" },
    { NESTED_TYPES_COMMAND, "NestedTypes" },
    { STATUS_COMMAND, "Status" },
    { INTERFACES_COMMAND, "Interfaces" },
    { CLASS_OBJECT_COMMAND, "ClassObject" },
    { SOURCE_DEBUG_EXTENSION_COMMAND, "SourceDebugExtension" },
    { SIGNATURE_WITH_GENERIC_COMMAND, "SignatureWithGeneric" },
    { FIELDS_WITH_GENERIC_COMMAND, "FieldsWithGeneric" },
    { METHODS_WITH_GENERIC_COMMAND, "MethodsWithGeneric" },
    { INSTANCES_COMMAND, "Instances" },
    { CLASS_FILE_VERSION_COMMAND, "ClassFileVersion" },
    { CONSTANT_POOL_COMMAND, "ConstantPool" },
    { 0, NULL }
};

static const value_string classtype_commands[] = {
    { 1, "SuperClass" },
    { 2, "SetValues" },
    { 3, "InvokeMethods" },
    { 4, "NewInstance" },
    { 0, NULL }
};

static const value_string arraytype_commands[] = {
    { 1, "NewInstance" },
    { 0, NULL }
};

static const value_string interfacetype_commands[] = {
    { 1, "InvokeMethod" },
    { 0, NULL }
};

static const value_string method_commands[] = {
    { 1, "LineTable" },
    { 2, "VariableTable" },
    { 3, "Bytecodes" },
    { 4, "IsObsolete" },
    { 5, "VariableTableWithGeneric" },
    { 0, NULL }
};

static const value_string objectreference_commands[] = {
    { 1, "ReferenceType" },
    { 2, "GetValues" },
    { 3, "SetValues" },
    { 4, "MonitorInfo" },
    { 5, "InvokeMethod" },
    { 6, "DisableCollection" },
    { 7, "EnableCollection" },
    { 8, "IsCollected" },
    { 9, "ReferringObjects" },
    { 0, NULL }
};

static const value_string stringreference_commands[] = {
    { 1, "Value" },
    { 0, NULL }
};

static const value_string threadreference_commands[] = {
    { 1, "Name" },
    { 2, "Suspend" },
    { 3, "Resume" },
    { 4, "Status" },
    { 5, "ThreadGroup" },
    { 6, "Frames" },
    { 7, "FrameCount" },
    { 8, "OwnedMonitors" },
    { 9, "CurrentContentedMonitor" },
    { 10, "Stop" },
    { 11, "Interrupt" },
    { 12, "SuspendCount" },
    { 13, "OwnedMonitorsStackDepthInfo" },
    { 14, "ForceEarlyReturn" },
    { 0, NULL }
};

static const value_string threadgroupreference_commands[] = {
    { 1, "Name" },
    { 2, "Parent" },
    { 3, "Children" },
    { 0, NULL }
};

static const value_string arrayreference_commands[] = {
    { 1, "Length" },
    { 2, "GetValues" },
    { 3, "SetValues" },
    { 0, NULL }
};

static const value_string classloaderreference_commands[] = {
    { 1, "VisibleClasses" },
    { 0, NULL }
};

static const value_string eventrequest_commands[] = {
    { 1, "Set" },
    { 2, "Clear" },
    { 3, "ClearAllBreakpoints" },
    { 0, NULL }
};

static const value_string stackframe_commands[] = {
    { 1, "GetValues" },
    { 2, "SetValues" },
    { 3, "ThisObject" },
    { 4, "PopFrames" },
    { 0, NULL }
};

static const value_string classobjectreference_commands[] = {
    { 1, "ReflectedType" },
    { 0, NULL }
};

static const value_string event_commands[] = {
    { 100, "Composite" },
    { 0, NULL }
};

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_jdwp(void);
void proto_register_jdwp(void);

/* Initialize the protocol and registered fields */
static int proto_jdwp = -1;
static int hf_header = -1;
static int hf_length = -1;
static int hf_id = -1;
static int hf_flags = -1;
static int hf_replyflag = -1;
static int hf_errorcode = -1;
static int hf_commandset = -1;
static int hf_virtualmachine_command = -1;
static int hf_referencetype_command = -1;
static int hf_classtype_command = -1;
static int hf_arraytype_command = -1;
static int hf_interfacetype_command = -1;
static int hf_method_command = -1;
static int hf_objectreference_command = -1;
static int hf_stringreference_command = -1;
static int hf_threadreference_command = -1;
static int hf_threadgroupreference_command = -1;
static int hf_arrayreference_command = -1;
static int hf_classloaderreference_command = -1;
static int hf_eventrequest_command = -1;
static int hf_stackframe_command = -1;
static int hf_classobjectreference_command = -1;
static int hf_event_command = -1;
static int hf_data = -1;

static int hf_description = -1;
static int hf_jdwp_major = -1;
static int hf_jdwp_minor = -1;
static int hf_vm_version = -1;
static int hf_vm_name = -1;

static int hf_signature = -1;
static int hf_generic_signature = -1;
static int hf_class = -1;
static int hf_ref_type_tag = -1;

static int hf_reference_type_id_8 = -1;
static int hf_reference_type_id_16 = -1;
static int hf_reference_type_id_32 = -1;
static int hf_reference_type_id_64 = -1;

static int hf_class_status = -1;
static int hf_class_status_verified = -1;
static int hf_class_status_prepared = -1;
static int hf_class_status_initialized = -1;
static int hf_class_status_error = -1;

static int hf_field_id_size = -1;
static int hf_mehtod_id_size = -1;
static int hf_object_id_size = -1;
static int hf_reference_type_id_size = -1;
static int hf_frame_id_size = -1;


static int hf_thread_id_8 = -1;
static int hf_thread_id_16 = -1;
static int hf_thread_id_32 = -1;
static int hf_thread_id_64 = -1;

static int hf_thread_group_id_8 = -1;
static int hf_thread_group_id_16 = -1;
static int hf_thread_group_id_32 = -1;
static int hf_thread_group_id_64 = -1;

static int hf_classloader_id_8 = -1;
static int hf_classloader_id_16 = -1;
static int hf_classloader_id_32 = -1;
static int hf_classloader_id_64 = -1;


static int hf_exit_code = -1;

static int hf_utf = -1;
static int hf_string_id_8 = -1;
static int hf_string_id_16 = -1;
static int hf_string_id_32 = -1;
static int hf_string_id_64 = -1;

static int hf_field_id_8 = -1;
static int hf_field_id_16 = -1;
static int hf_field_id_32 = -1;
static int hf_field_id_64 = -1;

static int hf_method_id_8 = -1;
static int hf_method_id_16 = -1;
static int hf_method_id_32 = -1;
static int hf_method_id_64 = -1;

static int hf_interface_id_8 = -1;
static int hf_interface_id_16 = -1;
static int hf_interface_id_32 = -1;
static int hf_interface_id_64 = -1;

static int hf_class_object_id_8 = -1;
static int hf_class_object_id_16 = -1;
static int hf_class_object_id_32 = -1;
static int hf_class_object_id_64 = -1;

static int hf_stratum_id = -1;

static int hf_extension = -1;

static int hf_instance_count = -1;

static int hf_can_watch_field_modification = -1;
static int hf_can_watch_field_access = -1;
static int hf_can_get_byte_codes = -1;
static int hf_can_get_synthetic_attribute = -1;
static int hf_can_get_owned_monitor_info = -1;
static int hf_can_get_current_contented_monitor = -1;
static int hf_can_get_monitor_info = -1;
static int hf_can_redefine_classes = -1;
static int hf_can_add_method = -1;
static int hf_can_unrestrictedly_redefine_classes = -1;
static int hf_can_pop_frames = -1;
static int hf_can_use_instance_filters = -1;
static int hf_can_get_source_debug_extension = -1;
static int hf_can_request_vm_death_event = -1;
static int hf_can_set_default_stratum = -1;
static int hf_can_get_instance_info = -1;
static int hf_can_request_monitor_events = -1;
static int hf_can_get_monitor_frame_info = -1;
static int hf_can_use_source_name_filters = -1;
static int hf_can_get_constant_pool = -1;
static int hf_can_force_early_return = -1;

static int hf_modbits = -1;
static int hf_field = -1;
static int hf_method = -1;
static int hf_name = -1;
static int hf_source_file = -1;
static int hf_major_version = -1;
static int hf_minor_version = -1;
static int hf_cpbytes = -1;

/*static int hf_string_value = -1;

static int hf_thread_name = -1;

static int hf_frame_count = -1;
static int hf_throwable = -1;
static int hf_suspend_count = -1;

static int hf_group_name = -1; */


/* Initialize the subtree pointers */
static gint ett_jdwp = -1;
static gint ett_header = -1;
static gint ett_flags = -1;
static gint ett_data = -1;
static gint ett_class = -1;
static gint ett_class_status = -1;
static gint ett_field = -1;
static gint ett_method = -1;

typedef struct _idsizes_t
{
    guint32 field_id_size;
    guint32 method_id_size;
    guint32 object_id_size;
    guint32 reference_type_id_size;
    guint32 frame_id_size;
}idsizes_t;

typedef struct _command_t
{
    guint8 commandset;
    guint8 command;
}command_t;

typedef struct _conversation_info_t
{
  	wmem_map_t *commands1;
  	wmem_map_t *commands2;
  	idsizes_t idsizes;
       
}conversation_info_t;

static int dissect_jdwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_);



static guint tcp_port_pref = JDWP_TCP_PORT;




static guint8 JDWP_HANDSHAKE_BYTES[] = {'J', 'D', 'W', 'P', '-', 'H', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e' };



/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_jdwp(void)
{
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
		{ &hf_header,
        	{ "Header", "jdwp.header", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_length,
        	{ "Length", "jdwp.header.length", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_id,
        	{ "Id", "jdwp.header.id", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_flags,
        	{ "Flags", "jdwp.header.flags", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_replyflag,
        	{ "Reply", "jdwp.header.flags.reply", FT_BOOLEAN, 8, NULL,
            REPLY_FLAG, NULL, HFILL }},
       	{ &hf_errorcode,
        	{ "Error code", "jdwp.header.errorcode", FT_UINT16, BASE_DEC, VALS(errorcodes),
            0x0, NULL, HFILL }},
       	{ &hf_commandset,
        	{ "Command Set", "jdwp.header.commandset", FT_UINT8, BASE_DEC, VALS(commandsets),
            0x0, NULL, HFILL }},
       	{ &hf_virtualmachine_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(virtualmachine_commands),
            0x0, NULL, HFILL }},
       	{ &hf_referencetype_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(referencetype_commands),
            0x0, NULL, HFILL }},
       	{ &hf_classtype_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(classtype_commands),
            0x0, NULL, HFILL }},
       	{ &hf_arraytype_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(arraytype_commands),
            0x0, NULL, HFILL }},
       	{ &hf_interfacetype_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(interfacetype_commands),
            0x0, NULL, HFILL }},
       	{ &hf_method_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(method_commands),
            0x0, NULL, HFILL }},
       	{ &hf_objectreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(objectreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_stringreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(stringreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_threadreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(threadreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_threadgroupreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(threadgroupreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_arrayreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(arrayreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_classloaderreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(classloaderreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_eventrequest_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(eventrequest_commands),
            0x0, NULL, HFILL }},
       	{ &hf_stackframe_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(stackframe_commands),
            0x0, NULL, HFILL }},
       	{ &hf_classobjectreference_command,
        	{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(classobjectreference_commands),
            0x0, NULL, HFILL }},
       	{ &hf_event_command,
      		{ "Command", "jdwp.header.command", FT_UINT8, BASE_DEC, VALS(event_commands),
            0x0, NULL, HFILL }},
		{ &hf_data,
        	{ "Data", "jdwp.data", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_description,
        	{ "Description", "jdwp.data.description", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_jdwp_major,
        	{ "JDWP Major", "jdwp.data.jdwpmajor", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_jdwp_minor,
        	{ "JDWP Minor", "jdwp.data.jdwpminor", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_vm_version,
        	{ "VM Version", "jdwp.data.vmversion", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_vm_name,
        	{ "VM Name", "jdwp.data.vmname", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},     

       	{ &hf_reference_type_id_8,
        	{ "ReferenceTypeID", "jdwp.data.referencetypeid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_reference_type_id_16,
        	{ "ReferenceTypeID", "jdwp.data.referencetypeid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_reference_type_id_32,
        	{ "ReferenceTypeID", "jdwp.data.referencetypeid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_reference_type_id_64,
        	{ "ReferenceTypeID", "jdwp.data.referencetypeid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

		{ &hf_field_id_size,
        	{ "FieldIDSize", "jdwp.data.fieldidsize", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_mehtod_id_size,
        	{ "MethodIDSize", "jdwp.data.methodidsize", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_object_id_size,
        	{ "ObjectIDSize", "jdwp.data.objectidsize", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_reference_type_id_size,
        	{ "ReferenceTypeIDSize", "jdwp.data.referencetypeidsize", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_frame_id_size,
        	{ "FrameIDSize", "jdwp.data.frameidsize", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},    

       	{ &hf_signature,
        	{ "Signature", "jdwp.data.signature", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }}, 
       	{ &hf_generic_signature,
        	{ "GenericSignature", "jdwp.data.genericsignature", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }}, 
		

       	{ &hf_thread_id_8,
        	{ "ThreadID", "jdwp.data.threadid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_id_16,
        	{ "ThreadID", "jdwp.data.threadid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_id_32,
        	{ "ThreadID", "jdwp.data.threadid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_id_64,
        	{ "ThreadID", "jdwp.data.threadid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_classloader_id_8,
        	{ "ClassLoaderID", "jdwp.data.classloaderid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_classloader_id_16,
        	{ "ClassLoaderID", "jdwp.data.classloaderid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_classloader_id_32,
        	{ "ClassLoaderID", "jdwp.data.classloaderid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_classloader_id_64,
        	{ "ClassLoaderID", "jdwp.data.classloaderid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_thread_group_id_8,
        	{ "ThreadGroupID", "jdwp.data.threadgroupid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_group_id_16,
        	{ "ThreadGroupID", "jdwp.data.threadgroupid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_group_id_32,
        	{ "ThreadGroupID", "jdwp.data.threadgroupid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_thread_group_id_64,
        	{ "ThreadGroupID", "jdwp.data.threadgroupid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},


       	{ &hf_exit_code,
        	{ "ExitCode", "jdwp.data.exitcode", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }}, 

       	{ &hf_utf,
        	{ "Utf", "jdwp.data.utf", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},   
       	{ &hf_string_id_8,
        	{ "StringID", "jdwp.data.stringid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_string_id_16,
        	{ "StringID", "jdwp.data.stringid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_string_id_32,
        	{ "StringID", "jdwp.data.stringid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_string_id_64,
        	{ "StringID", "jdwp.data.stringid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_stratum_id,
        	{ "StratumID", "jdwp.data.stratumid", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_instance_count,
        	{ "InstanceCount", "jdwp.data.instancecount", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},  
       	{ &hf_class,
        	{ "Class", "jdwp.data.class", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},  
       	{ &hf_ref_type_tag,
        	{ "RefTypeTag", "jdwp.data.reftypetag", FT_UINT8, BASE_DEC, VALS(typetags),
            0x0, NULL, HFILL }},  
       	{ &hf_class_status,
        	{ "Status", "jdwp.data.status", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
		{ &hf_class_status_verified,
        	{ "Verified", "jdwp.data.status.verified", FT_BOOLEAN, 8, NULL,
            CLASS_STATUS_VERIFIED_FLAG, NULL, HFILL }},
		{ &hf_class_status_prepared,
        	{ "Prepared", "jdwp.data.status.prepared", FT_BOOLEAN, 8, NULL,
            CLASS_STATUS_PREPARED_FLAG, NULL, HFILL }},
		{ &hf_class_status_initialized,
        	{ "Initialized", "jdwp.data.status.initialized", FT_BOOLEAN, 8, NULL,
            CLASS_STATUS_INITIALIZED_FLAG, NULL, HFILL }},
		{ &hf_class_status_error,
        	{ "Error", "jdwp.data.status.error", FT_BOOLEAN, 8, NULL,
            CLASS_STATUS_ERROR_FLAG, NULL, HFILL }},
       	{ &hf_can_watch_field_modification,
        	{ "CanWatchFieldModification", "jdwp.data.canwatchfieldmodification", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_watch_field_access,
        	{ "CanWatchFieldAccess", "jdwp.data.canwatchfieldaccess", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_byte_codes,
        	{ "CanGetBytecodes", "jdwp.data.canwatchfieldmodification", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_synthetic_attribute,
        	{ "CanGetSyntheticAttribute", "jdwp.data.cangetsyntheticattribute", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_owned_monitor_info,
        	{ "CanGetOwnedMonitorInfo", "jdwp.data.cangetownedmonitorinfo", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_current_contented_monitor,
        	{ "CanGetCurrentContendedMonitor", "jdwp.data.cangetcurrentcontendedmonitor", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_monitor_info,
        	{ "CanGetMonitorInfo", "jdwp.data.cangetmonitorinfo", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_redefine_classes,
        	{ "CanRedefineClasses", "jdwp.data.canredefineclasses", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_add_method,
        	{ "CanAddMethod", "jdwp.data.canaddmethod", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_unrestrictedly_redefine_classes,
        	{ "CanUnrestrictedlyRedefineClasses", "jdwp.data.canunrestrictedlyfedefineclasses", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_pop_frames,
        	{ "CanPopFrames", "jdwp.data.canpopframes", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_use_instance_filters,
        	{ "CanUseInstanceFilters", "jdwp.data.canuseinstancefilters", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_source_debug_extension,
        	{ "CanGetSourceDebugExtension", "jdwp.data.cangetsourcedebugextension", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_request_vm_death_event,
        	{ "CanRequestVMDeathEvent", "jdwp.data.canrequestvmdeathevent", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_set_default_stratum,
        	{ "CanSetDefaultStratum", "jdwp.data.cansetdefaultstratum", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_instance_info,
        	{ "CanGetInstanceInfo", "jdwp.data.cangetinstanceinfo", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_request_monitor_events,
        	{ "CanRequestMonitorEvents", "jdwp.data.canrequestmonitorevents", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_monitor_frame_info,
        	{ "CanGetMonitorFrameInfo", "jdwp.data.cangetmonitorframeinfo", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_use_source_name_filters,
        	{ "CanUseSourceNameFilters", "jdwp.data.canusesourcenamefilters", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_get_constant_pool,
        	{ "CanGetConstantPool", "jdwp.data.cangetconstantpool", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_can_force_early_return,
        	{ "CanForceEarlyReturn", "jdwp.data.canforceearlyreturn", FT_BOOLEAN, 8, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_modbits,
        	{ "ModBits", "jdwp.data.modbits", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_field,
        	{ "Field", "jdwp.data.field", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},  
       	{ &hf_method,
        	{ "Method", "jdwp.data.method", FT_NONE, BASE_NONE, NULL,
            0x0, NULL, HFILL }},  

       	{ &hf_field_id_8,
        	{ "FieldID", "jdwp.data.fieldid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_field_id_16,
        	{ "FieldID", "jdwp.data.fieldid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_field_id_32,
        	{ "FieldID", "jdwp.data.fieldid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_field_id_64,
        	{ "FieldID", "jdwp.data.fieldid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_method_id_8,
        	{ "MethodID", "jdwp.data.methodid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_method_id_16,
        	{ "MethodID", "jdwp.data.methodid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_method_id_32,
        	{ "MethodID", "jdwp.data.methodid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_method_id_64,
        	{ "MethodID", "jdwp.data.methodid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_name,
        	{ "Name", "jdwp.data.name", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_source_file,
        	{ "SourceFile", "jdwp.data.sourcefile", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_extension,
        	{ "Extension", "jdwp.data.extension", FT_UINT_STRING, BASE_NONE, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_interface_id_8,
        	{ "InterfaceID", "jdwp.data.interfaceid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_interface_id_16,
        	{ "InterfaceID", "jdwp.data.interfaceid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_interface_id_32,
        	{ "InterfaceID", "jdwp.data.interfaceid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_interface_id_64,
        	{ "InterfaceID", "jdwp.data.interfaceid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_class_object_id_8,
        	{ "ClassObjectID", "jdwp.data.classobjectid", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_class_object_id_16,
        	{ "ClassObjectID", "jdwp.data.classobjectid", FT_UINT16, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_class_object_id_32,
        	{ "ClassObjectID", "jdwp.data.classobjectid", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_class_object_id_64,
        	{ "ClassObjectID", "jdwp.data.classobjectid", FT_UINT64, BASE_DEC, NULL,
            0x0, NULL, HFILL }},

       	{ &hf_major_version,
        	{ "MajorVersion", "jdwp.data.majorversion", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_minor_version,
        	{ "MinorVersion", "jdwp.data.minorversion", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL }},
       	{ &hf_cpbytes,
        	{ "ConstantPoolBytes", "jdwp.data.cpbytes", FT_UINT_BYTES, BASE_NONE, NULL,
            0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_jdwp,
        &ett_header,
        &ett_flags,
        &ett_data,
		&ett_class,
		&ett_class_status,
		&ett_field,
		&ett_method
    };

    /* Register the protocol name and description */
    proto_jdwp = proto_register_protocol("Java Debug Wire Protocol",
            "JDWP", "jdwp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_jdwp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register a preferences module
     */
    prefs_register_protocol(proto_jdwp,
            proto_reg_handoff_jdwp);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_jdwp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t jdwp_handle;
    static int current_port;

    if (!initialized) {
        /* Use new_create_dissector_handle() to indicate that
         * dissect_PROTOABBREV() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to PROTONAME).
         */
        jdwp_handle = new_create_dissector_handle(dissect_jdwp,
                proto_jdwp);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the PROTOABBREV_handle and the value the preference had at the time
         * you registered.  The PROTOABBREV_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("tcp.port", current_port, jdwp_handle);
    }

    current_port = tcp_port_pref;

    dissector_add_uint("tcp.port", current_port, jdwp_handle);
}

/* determine PDU length of protocol JDWP */
static guint get_jdwp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint8 *handshake_buffer;
    
    if(tvb_reported_length(tvb) == JDWP_HANDSHAKE_BYTES_COUNT)
    {
        handshake_buffer = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, JDWP_HANDSHAKE_BYTES_COUNT, ENC_UTF_8);
        if(memcmp(handshake_buffer, JDWP_HANDSHAKE_BYTES, JDWP_HANDSHAKE_BYTES_COUNT) == 0)
        {
            return JDWP_HANDSHAKE_BYTES_COUNT;
        }
    }

    return tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
}

static gboolean is_reply(guint8 flags)
{
	return (flags & REPLY_FLAG) != 0;
}

static int get_hf_id_ref(int *hf_id_refs, guint32 idsize)
{
	switch(idsize)
	{
		case 1:
			return hf_id_refs[0];
		case 2:
			return hf_id_refs[1];
		case 4:
			return hf_id_refs[2];
		case 8:
			return hf_id_refs[3];
		default:
			return 0;
	}
}

static int get_hf_reference_type_id_ref(guint32 idsize)
{
	int hf_reference_type_ids[4];
	hf_reference_type_ids[0] = hf_reference_type_id_8;
	hf_reference_type_ids[1] = hf_reference_type_id_16;
	hf_reference_type_ids[2] = hf_reference_type_id_32;
	hf_reference_type_ids[3] = hf_reference_type_id_64;
	return get_hf_id_ref(hf_reference_type_ids, idsize);
}

static int get_hf_thread_id_ref(guint32 idsize)
{
	int hf_thread_ids[4];
	hf_thread_ids[0] = hf_thread_id_8;
	hf_thread_ids[1] = hf_thread_id_16;
	hf_thread_ids[2] = hf_thread_id_32;
	hf_thread_ids[3] = hf_thread_id_64;
	return get_hf_id_ref(hf_thread_ids, idsize);
}

static int get_hf_thread_group_id_ref(guint32 idsize)
{
	int hf_thread_group_ids[4];
	hf_thread_group_ids[0] = hf_thread_group_id_8;
	hf_thread_group_ids[1] = hf_thread_group_id_16;
	hf_thread_group_ids[2] = hf_thread_group_id_32;
	hf_thread_group_ids[3] = hf_thread_group_id_64;
	return get_hf_id_ref(hf_thread_group_ids, idsize);
}

static int get_hf_string_id_ref(guint32 idsize)
{
	int hf_string_ids[4];
	hf_string_ids[0] = hf_string_id_8;
	hf_string_ids[1] = hf_string_id_16;
	hf_string_ids[2] = hf_string_id_32;
	hf_string_ids[3] = hf_string_id_64;
	return get_hf_id_ref(hf_string_ids, idsize);
}

static int get_hf_classloader_id_ref(guint32 idsize)
{
	int hf_classloader_ids[4];
	hf_classloader_ids[0] = hf_classloader_id_8;
	hf_classloader_ids[1] = hf_classloader_id_16;
	hf_classloader_ids[2] = hf_classloader_id_32;
	hf_classloader_ids[3] = hf_classloader_id_64;
	return get_hf_id_ref(hf_classloader_ids, idsize);
}

static int get_hf_field_id_ref(guint32 idsize)
{
	int hf_field_ids[4];
	hf_field_ids[0] = hf_field_id_8;
	hf_field_ids[1] = hf_field_id_16;
	hf_field_ids[2] = hf_field_id_32;
	hf_field_ids[3] = hf_field_id_64;
	return get_hf_id_ref(hf_field_ids, idsize);
}

static int get_hf_method_id_ref(guint32 idsize)
{
	int hf_method_ids[4];
	hf_method_ids[0] = hf_method_id_8;
	hf_method_ids[1] = hf_method_id_16;
	hf_method_ids[2] = hf_method_id_32;
	hf_method_ids[3] = hf_method_id_64;
	return get_hf_id_ref(hf_method_ids, idsize);
}

static int get_hf_interface_id_ref(guint32 idsize)
{
	int hf_interface_ids[4];
	hf_interface_ids[0] = hf_interface_id_8;
	hf_interface_ids[1] = hf_interface_id_16;
	hf_interface_ids[2] = hf_interface_id_32;
	hf_interface_ids[3] = hf_interface_id_64;
	return get_hf_id_ref(hf_interface_ids, idsize);
}

static int get_hf_class_object_id_ref(guint32 idsize)
{
	int hf_class_object_ids[4];
	hf_class_object_ids[0] = hf_class_object_id_8;
	hf_class_object_ids[1] = hf_class_object_id_16;
	hf_class_object_ids[2] = hf_class_object_id_32;
	hf_class_object_ids[3] = hf_class_object_id_64;
	return get_hf_id_ref(hf_class_object_ids, idsize);
}


static void dissect_jdwp_class_status(tvbuff_t *tvb, proto_tree *tree, guint32 *offset)
{
	proto_item *class_status_item;
    proto_tree *class_status_tree;

	class_status_item = proto_tree_add_item(tree, hf_class_status, tvb, *offset, -1, ENC_NA);
    class_status_tree = proto_item_add_subtree(class_status_item, ett_class_status);
	proto_tree_add_item(class_status_tree, hf_class_status_verified, tvb, *offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(class_status_tree, hf_class_status_prepared, tvb, *offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(class_status_tree, hf_class_status_initialized, tvb, *offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(class_status_tree, hf_class_status_error, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 4;
}

static void dissect_jdwp_string(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, int hf_string)
{
	proto_tree_add_item(tree, hf_string, tvb, *offset, 4, ENC_UTF_8);
    *offset += 4 + tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
}

static void dissect_jdwp_signature(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, gboolean with_generic)
{
	dissect_jdwp_string(tvb, tree, offset, hf_signature);
	
	if(with_generic == TRUE)
	{
		dissect_jdwp_string(tvb, tree, offset, hf_generic_signature);
	}
}

static void dissect_jdwp_class(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 object_id_size, int hf_reference_type_id,  gboolean with_status, gboolean with_signature, gboolean with_generic)
{
	proto_item *class_item;
    proto_tree *class_tree;

	class_item = proto_tree_add_item(tree, hf_class, tvb, *offset, -1, ENC_NA);
    class_tree = proto_item_add_subtree(class_item, ett_class);
	proto_tree_add_item(class_tree, hf_ref_type_tag, tvb, *offset, 1, ENC_BIG_ENDIAN);
    *offset += 1;					
	proto_tree_add_item(class_tree, hf_reference_type_id, tvb, *offset, object_id_size, ENC_BIG_ENDIAN);
	*offset += object_id_size;
	
	if(with_signature == TRUE)
	{
		dissect_jdwp_signature(tvb, class_tree, offset, with_generic);
	}

	if(with_status == TRUE)
	{
		dissect_jdwp_class_status(tvb, class_tree, offset);
	}

}

static void dissect_jdwp_classes(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 object_id_size, gboolean with_status, gboolean with_signature, gboolean with_generic)
{
	guint32 class_count;
	int hf_reference_type_id;

	class_count = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
	*offset += 4;

	hf_reference_type_id = get_hf_reference_type_id_ref(object_id_size);
				
	for(; class_count > 0; class_count--)
	{
		dissect_jdwp_class(tvb, tree, offset, object_id_size, hf_reference_type_id, with_status, with_signature, with_generic);
	}
}

static void dissect_jdwp_field(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 field_id_size, int hf_field_id, gboolean with_generic)
{
	proto_item *field_item;
    proto_tree *field_tree;

	field_item = proto_tree_add_item(tree, hf_field, tvb, *offset, -1, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_field);
	proto_tree_add_item(field_tree, hf_field_id, tvb, *offset, field_id_size, ENC_BIG_ENDIAN);
	*offset += field_id_size;
	dissect_jdwp_string(tvb, field_tree, offset, hf_name);
	dissect_jdwp_signature(tvb, field_tree, offset, with_generic);
	proto_tree_add_item(field_tree, hf_modbits, tvb, *offset, 4, ENC_BIG_ENDIAN);
	*offset += 4;
}

static void dissect_jdwp_fields(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 field_id_size, gboolean with_generic)
{
	guint32 field_count;
	int hf_field_id;

	field_count = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
	*offset += 4;

	hf_field_id = get_hf_field_id_ref(field_id_size);
				
	for(; field_count > 0; field_count--)
	{
		dissect_jdwp_field(tvb, tree, offset, field_id_size, hf_field_id, with_generic);
	}
}

static void dissect_jdwp_method(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 method_id_size, int hf_method_id, gboolean with_generic)
{
	proto_item *method_item;
    proto_tree *method_tree;

	method_item = proto_tree_add_item(tree, hf_method, tvb, *offset, -1, ENC_NA);
    method_tree = proto_item_add_subtree(method_item, ett_method);
	proto_tree_add_item(method_tree, hf_method_id, tvb, *offset, method_id_size, ENC_BIG_ENDIAN);
	*offset += method_id_size;
	dissect_jdwp_string(tvb, method_tree, offset, hf_name);
	dissect_jdwp_signature(tvb, method_tree, offset, with_generic);
	proto_tree_add_item(method_tree, hf_modbits, tvb, *offset, 4, ENC_BIG_ENDIAN);
	*offset += 4;
}

static void dissect_jdwp_methods(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 method_id_size, gboolean with_generic)
{
	guint32 method_count;
	int hf_method_id;

	method_count = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
	*offset += 4;

	hf_method_id = get_hf_method_id_ref(method_id_size);
				
	for(; method_count > 0; method_count--)
	{
		dissect_jdwp_method(tvb, tree, offset, method_id_size, hf_method_id, with_generic);
	}
}

static void dissect_jdwp_capabilities(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, gboolean with_new)
{
	proto_tree_add_item(tree, hf_can_watch_field_modification, tvb, *offset, 1, ENC_UTF_8);
	*offset += 1;
	proto_tree_add_item(tree, hf_can_watch_field_access, tvb, *offset, 1, ENC_UTF_8);
	*offset += 1;
	proto_tree_add_item(tree, hf_can_get_byte_codes, tvb, *offset, 1, ENC_UTF_8);
	*offset += 1;
	proto_tree_add_item(tree, hf_can_get_synthetic_attribute, tvb, *offset, 1, ENC_UTF_8);
	*offset += 1;
	proto_tree_add_item(tree, hf_can_get_owned_monitor_info, tvb, *offset, 1, ENC_UTF_8);
	*offset += 1;

	if(with_new == TRUE)
	{
		proto_tree_add_item(tree, hf_can_get_current_contented_monitor, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_get_monitor_info, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_redefine_classes, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_unrestrictedly_redefine_classes, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_pop_frames, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_use_instance_filters, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_get_source_debug_extension, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_request_vm_death_event, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_set_default_stratum, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_get_instance_info, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_request_monitor_events, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_get_monitor_frame_info, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_use_source_name_filters, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_get_constant_pool, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
		proto_tree_add_item(tree, hf_can_force_early_return, tvb, *offset, 1, ENC_UTF_8);
		*offset += 1;
	}
}

void dissect_jdwp_ids(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, guint32 id_size, int hf_ref_id)
{
	guint32 id_count;
	
	id_count = tvb_get_guint32(tvb, *offset, ENC_BIG_ENDIAN);
	*offset += 4;
				
	for(; id_count > 0; id_count--)
	{
		proto_tree_add_item(tree, hf_ref_id, tvb, *offset, id_size, ENC_BIG_ENDIAN);
		*offset += id_size;
	}
}

/*static void dissect_jdwp_value(tvbuff_t *tvb, proto_tree *tree, guint32 *offset)
{
	proto_item *value_item;
    proto_tree *value_tree;
	guint8 tag;

	value_item = proto_tree_add_item(tree, hf_value, tvb, *offset, -1, ENC_NA);
    value_status_tree = proto_item_add_subtree(value_item, ett_value);
	tag = tvb_get_guint8(tvb, *offset);
	proto_tree_add_item(value_tree, hf_tag, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 1;

	switch(tag)
	{
		case ARRAY:
			break;
		
		case BYTE:
			break;

		case CHAR:
			break;
		
		case OBJECT:
			break;

		case FLOAT:
			break;
		
		case DOUBLE:
			break;

		case INT:
			break;
		
		case LONG:
			break;

		case SHORT:
			break;
		
		case VOID:
			break;

		case BOOLEAN:
			break;
		
		case STRING:
			break;

		case THREAD:
			break;
		
		case THREAD_GROUP:
			break;

		case CLASS_LOADER:
			break;
		
		case CLASS_OBJECT:
			break;

		default:
			break;
	}

	proto_tree_add_item(class_status_tree, hf_class_status_error, tvb, *offset, 1, ENC_BIG_ENDIAN);
	*offset += 4;
}*/

static void dissect_jdwp_vm_commandset_message_tree(tvbuff_t *tvb, proto_tree *data_tree, guint32 offset, guint8 flags, guint8 command, idsizes_t *idsizes)
{
	guint32 object_id_size;

	object_id_size = idsizes->object_id_size;

	switch(command)
	{
		case VERSION_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_string(tvb, data_tree, &offset, hf_description);
				proto_tree_add_item(data_tree, hf_jdwp_major, tvb, offset, 4, ENC_BIG_ENDIAN);
    			offset += 4;
				proto_tree_add_item(data_tree, hf_jdwp_minor, tvb, offset, 4, ENC_BIG_ENDIAN);
    			offset += 4;
				dissect_jdwp_string(tvb, data_tree, &offset, hf_vm_version);
				dissect_jdwp_string(tvb, data_tree, &offset, hf_vm_name);
			}
			break;

		case CLASSES_BY_SIGNATURE_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_classes(tvb, data_tree, &offset, object_id_size, TRUE, FALSE, FALSE);
			}
			else
			{
				proto_tree_add_item(data_tree, hf_signature, tvb, offset, 4, ENC_UTF_8);
			}
			break;

		case ALL_CLASSES_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_classes(tvb, data_tree, &offset, object_id_size, TRUE, TRUE, FALSE);	
			}
			break;

		case ALL_THREADS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_ids(tvb, data_tree, &offset, object_id_size, get_hf_thread_id_ref(object_id_size));
			}
			break;

		case TOP_LEVEL_THREAD_GROUPS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_ids(tvb, data_tree, &offset, object_id_size, get_hf_thread_group_id_ref(object_id_size));
			}
			break;

		case IDSIZES_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_field_id_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				idsizes->field_id_size = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    			offset += 4;
				proto_tree_add_item(data_tree, hf_mehtod_id_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				idsizes->method_id_size = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    			offset += 4;
				proto_tree_add_item(data_tree, hf_object_id_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				idsizes->object_id_size = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    			offset += 4;
				proto_tree_add_item(data_tree, hf_reference_type_id_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				idsizes->reference_type_id_size = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    			offset += 4;
				proto_tree_add_item(data_tree, hf_frame_id_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				idsizes->frame_id_size = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
			}
			break;

		case EXIT_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_exit_code, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			break;

		case CREATE_STRING_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, get_hf_string_id_ref(object_id_size), tvb, offset, object_id_size, ENC_BIG_ENDIAN);
			}
			else
			{
				dissect_jdwp_string(tvb, data_tree, &offset, hf_utf);
			}
			break;

		case CAPABILITIES_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_capabilities(tvb, data_tree, &offset, FALSE);
			}
			break;

		case CLASSPATHS_COMMAND:
			break;

		case DISPOSE_OBJECTS_COMMAND:
			break;

		case CAPABILITIES_NEW_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_capabilities(tvb, data_tree, &offset, TRUE);
			}
			break;

		case REDEFINE_CLASSES_COMMAND:
			break;

		case SET_DEFAULT_STRATUM_COMMAND:
			if(is_reply(flags) == FALSE)
			{
				dissect_jdwp_string(tvb, data_tree, &offset, hf_stratum_id);
			}
			break;

		case ALL_CLASSES_WITH_GENERIC_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_classes(tvb, data_tree, &offset, object_id_size, TRUE, TRUE, TRUE);	
			}
			break;

		case INSTANCE_COUNTS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				guint32 count = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
				offset += 4;
				
				for(; count > 0; count--)
				{
					proto_tree_add_item(data_tree, hf_instance_count, tvb, offset, 8, ENC_BIG_ENDIAN);
					offset += 8;
				}
			}
			else
			{
				dissect_jdwp_ids(tvb, data_tree, &offset, object_id_size, get_hf_reference_type_id_ref(object_id_size));
			}
			break;
			
		default:
			break;
	}
}

static void dissect_jdwp_reference_type_commandset_message_tree(tvbuff_t *tvb, proto_tree *data_tree, guint32 offset, guint8 flags, guint8 command, idsizes_t *idsizes)
{
	switch(command)
	{
		case SIGNATURE_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_signature(tvb, data_tree, &offset, FALSE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;
		case CLASSLOADER_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, get_hf_classloader_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case MODIFIERS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_modbits, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case FIELDS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_fields(tvb, data_tree, &offset, idsizes->field_id_size, FALSE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case METHODS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_methods(tvb, data_tree, &offset, idsizes->method_id_size, FALSE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case GET_VALUES_COMMAND:
			if(is_reply(flags) == FALSE)
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
				offset += idsizes->object_id_size;
				dissect_jdwp_ids(tvb, data_tree, &offset, idsizes->field_id_size, get_hf_field_id_ref(idsizes->field_id_size));
			}
			break;

		case SOURCE_FILE_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_source_file, tvb, offset, 4, ENC_UTF_8);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case NESTED_TYPES_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_source_file, tvb, offset, 4, ENC_UTF_8);
			}
			else
			{
				dissect_jdwp_classes(tvb, data_tree, &offset, idsizes->object_id_size, FALSE, FALSE, FALSE);	
			}
			break;

		case STATUS_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_class_status(tvb, data_tree, &offset);
			}
			else
			{
				dissect_jdwp_classes(tvb, data_tree, &offset, idsizes->object_id_size, FALSE, FALSE, FALSE);	
			}
			break;

		case INTERFACES_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_ids(tvb, data_tree, &offset, idsizes->object_id_size, get_hf_interface_id_ref(idsizes->object_id_size));
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case CLASS_OBJECT_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_ids(tvb, data_tree, &offset, idsizes->object_id_size, get_hf_class_object_id_ref(idsizes->object_id_size));
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case SOURCE_DEBUG_EXTENSION_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_string(tvb, data_tree, &offset, hf_extension);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case SIGNATURE_WITH_GENERIC_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_signature(tvb, data_tree, &offset, TRUE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case FIELDS_WITH_GENERIC_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_fields(tvb, data_tree, &offset, idsizes->field_id_size, TRUE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case METHODS_WITH_GENERIC_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				dissect_jdwp_methods(tvb, data_tree, &offset, idsizes->method_id_size, TRUE);
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case INSTANCES_COMMAND:
			break;

		case CLASS_FILE_VERSION_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				proto_tree_add_item(data_tree, hf_major_version, tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(data_tree, hf_minor_version, tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
				offset += 4;
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;

		case CONSTANT_POOL_COMMAND:
			if(is_reply(flags) == TRUE)
			{
				guint32 count = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
				offset += 4;
				
				for(; count > 0; count--)
				{
					proto_tree_add_item(data_tree, hf_cpbytes, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4 + tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
				}
			}
			else
			{
				proto_tree_add_item(data_tree, get_hf_reference_type_id_ref(idsizes->object_id_size), tvb, offset, idsizes->object_id_size, ENC_BIG_ENDIAN);
			}
			break;
			
		default:
			break;
	}
}

static void dissect_jdwp_message_tree(tvbuff_t *tvb, proto_tree *tree, guint32 length, guint8 flags, command_t *command, idsizes_t *idsizes)
{
    guint32 offset;
    proto_item *jdwp_item;
    proto_tree *jdwp_tree;
    proto_item *header_item;
    proto_tree *header_tree;
    proto_item *flags_item;
    proto_tree *flags_tree;
	proto_item *data_item;
    proto_tree *data_tree;
	void (*commandset_dissector)(tvbuff_t *, proto_tree *, guint32, guint8, guint8, idsizes_t *);

    /* JDWP */
    offset = 0;    
    jdwp_item = proto_tree_add_item(tree, proto_jdwp, tvb, 0, length, ENC_NA);
    jdwp_tree = proto_item_add_subtree(jdwp_item, ett_jdwp);

    /* Header */
    header_item = proto_tree_add_item(jdwp_tree, hf_header, tvb, offset, JDWP_HEADER_SIZE, ENC_BIG_ENDIAN);
    header_tree = proto_item_add_subtree(header_item, ett_header);
    proto_tree_add_item(header_tree, hf_length, tvb, 0, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(header_tree, hf_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    
    /* Flags */    
    flags_item = proto_tree_add_item(header_tree, hf_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(flags_item, ett_flags);
    proto_tree_add_item(flags_tree, hf_replyflag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if(is_reply(flags) == TRUE)
    {
        /* Error code */
        proto_tree_add_item(header_tree, hf_errorcode, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else
    {   
        /* Command Set & Command */
        proto_tree_add_item(header_tree, hf_commandset, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch(command->commandset)
        {
            case VM_COMMANDSET:
                proto_tree_add_item(header_tree, hf_virtualmachine_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case REFERENCE_TYPE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_referencetype_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case CLASS_TYPE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_classtype_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case ARRAY_TYPE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_arraytype_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case INTERFACE_TYPE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_interfacetype_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case METHOD_COMMANDSET:
                proto_tree_add_item(header_tree, hf_method_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case OBJECT_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_objectreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case STRING_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_stringreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case THREAD_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_threadreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case THREAD_GROUP_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_threadgroupreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case ARRAY_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_arrayreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case CLASSLOADER_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_classloaderreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case EVENT_REQUEST_COMMANDSET:
                proto_tree_add_item(header_tree, hf_eventrequest_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case STACK_FRAME_COMMANDSET:
                proto_tree_add_item(header_tree, hf_stackframe_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case CLASS_OBJECT_REFERENCE_COMMANDSET:
                proto_tree_add_item(header_tree, hf_classobjectreference_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            case EVENT_COMMANDSET:
                proto_tree_add_item(header_tree, hf_event_command, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;

            default:
                break;
        }
		offset++;
    }
	
	commandset_dissector = NULL;
	switch(command->commandset)
   	{
    	case VM_COMMANDSET:
			commandset_dissector = dissect_jdwp_vm_commandset_message_tree;
         	break;

     	case REFERENCE_TYPE_COMMANDSET:
			commandset_dissector = dissect_jdwp_reference_type_commandset_message_tree;
       		break;

     	case CLASS_TYPE_COMMANDSET:
           	break;

      	case ARRAY_TYPE_COMMANDSET:
          	break;

      	case INTERFACE_TYPE_COMMANDSET:
          	break;

      	case METHOD_COMMANDSET:
        	break;

     	case OBJECT_REFERENCE_COMMANDSET:
         	break;

    	case STRING_REFERENCE_COMMANDSET:
         	break;

    	case THREAD_REFERENCE_COMMANDSET:
         	break;

     	case THREAD_GROUP_REFERENCE_COMMANDSET:
          	break;

      	case ARRAY_REFERENCE_COMMANDSET:
         	break;

    	case CLASSLOADER_REFERENCE_COMMANDSET:
        	break;

     	case EVENT_REQUEST_COMMANDSET:
        	break;

    	case STACK_FRAME_COMMANDSET:
        	break;

    	case CLASS_OBJECT_REFERENCE_COMMANDSET:
          	break;

    	case EVENT_COMMANDSET:
         	break;

    	default:
          	break;
  	}

	/* Data */    
	if(commandset_dissector != NULL)
	{
		data_item = proto_tree_add_item(jdwp_tree, hf_data, tvb, offset, length - JDWP_HEADER_SIZE, ENC_NA);
		data_tree = proto_item_add_subtree(data_item, ett_data);
		commandset_dissector(tvb, data_tree, offset, flags, command->command, idsizes);
	}		
}

/* Find or create the conversation info if it does not exist. */
static conversation_info_t *find_or_create_conversation_info(conversation_t *conversation)
{
	conversation_info_t *conversation_info;
    conversation_info = (conversation_info_t *) conversation_get_proto_data(conversation, proto_jdwp);

  	if(conversation_info == NULL)
 	{
  		conversation_info = (conversation_info_t *) wmem_alloc(wmem_file_scope(), sizeof(conversation_info_t));
      	conversation_info->commands1 = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
     	conversation_info->commands2 = wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);
     	conversation_add_proto_data(conversation, proto_jdwp, conversation_info);
  	}

 	return conversation_info;
}

static command_t *get_command(tvbuff_t *tvb, packet_info *pinfo, conversation_t *conversation, conversation_info_t *conversation_info, guint32 offset, guint32 *id, guint8 flags)
{
	wmem_map_t *commands;
	command_t *command;

	if(is_reply(flags) == TRUE)
  	{   
      	if(cmp_address(&pinfo->dst, &conversation->key_ptr->addr1) == 0 && (pinfo->destport == conversation->key_ptr->port1))
	  	{
        	commands = conversation_info->commands1;
	  	}else
      	{
         	commands = conversation_info->commands2;
       	}
		command = (command_t *) wmem_map_lookup(commands, id);
	}
  	else
  	{
  		if(cmp_address(&pinfo->src, &conversation->key_ptr->addr1) == 0 && (pinfo->srcport == conversation->key_ptr->port1))
		{
  			commands = conversation_info->commands1;
		}else
     	{
         	commands = conversation_info->commands2;
      	}

    	command = (command_t *) wmem_alloc(wmem_file_scope(), sizeof(command_t));
      	command->commandset = tvb_get_guint8(tvb, offset);
     	offset++;
     	command->command = tvb_get_guint8(tvb, offset);
      	offset++;
     	wmem_map_insert(commands, id, command);
	}
	return command;
}

/* Code to actually dissect the packets */
static int dissect_jdwp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    guint32 captured_length;
	guint32 offset;
	guint32 length;
	guint32 *id;
	guint8 flags;
	command_t *command;
	conversation_t *conversation;
    conversation_info_t *conversation_info;

    captured_length = tvb_captured_length(tvb);
	offset = 0;
    length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
	offset += 4;
	
	col_clear(pinfo->cinfo, COL_INFO);
    
    /* Handshake */
    if(length != captured_length && captured_length == JDWP_HANDSHAKE_BYTES_COUNT)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Handshake");
    }
    /* Normal case */
    else if(length == captured_length && length >= JDWP_HEADER_SIZE)
    {
		id = (guint32 *) wmem_alloc(wmem_file_scope(), sizeof(guint32));
		*id = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
        offset += 4;
		flags = tvb_get_guint8(tvb, offset);
        offset++;
	
		conversation = find_or_create_conversation(pinfo);
		conversation_info = find_or_create_conversation_info(conversation);
		command = get_command(tvb, pinfo, conversation, conversation_info, offset, id, flags);

		if(is_reply(flags) == TRUE)
		{
			col_add_fstr(pinfo->cinfo, COL_INFO, "Reply [%u]", *id);
		}
		else
		{
        	col_add_fstr(pinfo->cinfo, COL_INFO, "Command [%u]", *id);
		}

        /* Wireshark needs the protocol tree information. */
        if(tree != NULL)
        {
            dissect_jdwp_message_tree(tvb, tree, length, flags, command, &conversation_info->idsizes);
        }
    }
    else{
        /* Not a JDWP message. */
        return 0;
    }

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "JDWP");
    return captured_length;
}

static int dissect_jdwp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_jdwp_message_len, dissect_jdwp_message, data);
    return tvb_captured_length(tvb);   
}
