/* Prototypes */
#include <switch.h>
#include <switch_types.h>

typedef enum {
	PROTOCOL_CALLBACK = -1,
	PROTOCOL_TCP = 0,
	PROTOCOL_TLS,
	PROTOCOL_UDP,
	PROTOCOL_WS,
	PROTOCOL_WSS
} protocol_type_t;

typedef struct {
	char *name;
	protocol_type_t type;
	char *uri;
	char *profile;
} protocol_t;

typedef enum {
	COMMAND_PRE,
	COMMAND_SEND,
	COMMAND_FIELD,
	COMMAND_REPLY,
	COMMAND_SET,
	COMMAND_APP,
	COMMAND_API,
	COMMAND_CREATE_EVENT,
	COMMAND_EVENT,
	COMMAND_CONDITION
} command_type_t;

typedef struct {
	command_type_t type;
	char *data1;
	char *data2;
	char *data3;
	command_t *next;
	command_t *child;
} command_t;

typedef enum { XML, JSON } profile_serialization_t;

static void *do_command_send(command_t *command, profile_serialization_t serialization) {}
static void *do_command_reply(command_t *command, profile_serialization_t serialization) {}
static void *do_command_event(command_t *command, profile_serialization_t serialization) {}
static void do_command(command_t *command, profile_serialization_t serialization)
{
	int doChild = 1;

	if (!command) { return; }
	switch (command->type) {
	case COMMAND_SEND:
		do_command_send(command, serialization);
		break;
	case COMMAND_REPLY:
		do_command_reply(command, serialization);
		break;

	case COMMAND_APP:
		/* code */
		break;
	case COMMAND_API:
		/* code */
		break;
	case COMMAND_CREATE_EVENT:
		break;
	case COMMAND_EVENT:
		do_command_event(command, serialization);
		break;
	case COMMAND_CONDITION:
		// doChild = 0;
		break;

	default:
		break;
	}

	if (doChild) { do_command(command->child, serialization); }
	do_command(command->next, serialization);

	return (void *)0;
}

typedef struct {
	char *name;
	profile_serialization_t serialization;
	int timeout;
	command_t *pre;
	command_t *child;
	command_t *timeout_name;
} profile_t;

#define MAX_ACL 100
static struct {
	switch_memory_pool_t *pool;
	switch_hash_t *protocol_hash;
	switch_hash_t *profile_hash;
	switch_hash_t *timeout_hash;
	switch_event_node_t *node;

	int port;
	int default_timeout;
	switch_bool_t stop_on_bind_error;
	char *acl[MAX_ACL];
} globals;

#define CONTROL_EVENT "control"
#define CONTROL_PREFIX "control_"
#define CONTROL_VARIABLE_PREFIX "variable_control_"

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_control_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_control_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_control_load);
SWITCH_MODULE_DEFINITION(mod_control, mod_control_load, mod_control_shutdown, NULL);

switch_status_t list_protocols(const char *line, const char *cursor, switch_console_callback_match_t **matches)
{
	return list_protocols_all(line, cursor, matches, SWITCH_FALSE);
}

switch_status_t list_protocols_callback(const char *line, const char *cursor, switch_console_callback_match_t **matches)
{
	return list_protocols_all(line, cursor, matches, SWITCH_TRUE);
}

switch_status_t list_protocols_all(const char *line, const char *cursor, switch_console_callback_match_t **matches,
								   switch_bool_t only_callback)
{
	protocol_t *protocol = NULL;
	switch_hash_index_t *hi;
	void *val;
	const void *vvar;
	switch_console_callback_match_t *my_matches = NULL;
	switch_status_t status = SWITCH_STATUS_FALSE;

	switch_mutex_lock(globals.protocol_hash);
	for (hi = switch_core_hash_first(globals.protocol_hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, &vvar, NULL, &val);

		protocol = (protocol_t *)val;
		if (strcmp((char *)vvar, protocol->name)) { continue; }

		if (!only_callback || PROTOCOL_CALLBACK == protocol->profile) {
			switch_console_push_match(&my_matches, (const char *)vvar);
		}
	}
	switch_mutex_unlock(globals.protocol_hash);

	if (my_matches) {
		*matches = my_matches;
		status = SWITCH_STATUS_SUCCESS;
	}

	return status;
}

switch_status_t list_profiles(const char *line, const char *cursor, switch_console_callback_match_t **matches)
{
	profile_t *profile = NULL;
	switch_hash_index_t *hi;
	void *val;
	const void *vvar;
	switch_console_callback_match_t *my_matches = NULL;
	switch_status_t status = SWITCH_STATUS_FALSE;

	switch_mutex_lock(globals.protocol_hash);
	for (hi = switch_core_hash_first(globals.protocol_hash); hi; hi = switch_core_hash_next(&hi)) {
		switch_core_hash_this(hi, &vvar, NULL, &val);

		profile = (profile_t *)val;
		if (strcmp((char *)vvar, profile->name)) { continue; }

		switch_console_push_match(&my_matches, (const char *)vvar);
	}
	switch_mutex_unlock(globals.protocol_hash);

	if (my_matches) {
		*matches = my_matches;
		status = SWITCH_STATUS_SUCCESS;
	}

	return status;
}

#define CONTROL_APP_DESC "Control or Print mod_control profile."
#define CONTROL_APP_USAGE "protocol | profile | [on | off] <profile-name>"
SWITCH_STANDARD_APP(control_app_function) {}

#define CONTROL_API_DESC "Let channel use mod_control's profile."
#define CONTROL_API_SYNTAX "<profile-name> <uuid>"
SWITCH_STANDARD_API(control_api_function) {}

static switch_status_t load_config(int reload, int del_all)
{


	return SWITCH_STATUS_SUCCESS;
}

static void fifo_member_add(char *fifo_name, char *originate_string, int simo_count, int timeout, int lag,
							time_t expires, int taking_calls)
{
	char digest[SWITCH_MD5_DIGEST_STRING_SIZE] = {0};
	char *sql, *name_dup, *p;
	char outbound_count[80] = "";
	callback_t cbt = {0};
	fifo_node_t *node = NULL;

	if (!fifo_name) return;

	if (switch_stristr("fifo_outbound_uuid=", originate_string)) {
		extract_fifo_outbound_uuid(originate_string, digest, sizeof(digest));
	} else {
		switch_md5_string(digest, (void *)originate_string, strlen(originate_string));
	}

	sql = switch_mprintf("delete from fifo_outbound where fifo_name='%q' and uuid = '%q'", fifo_name, digest);
	switch_assert(sql);
	fifo_execute_sql_queued(&sql, SWITCH_TRUE, SWITCH_TRUE);

	switch_mutex_lock(globals.mutex);
	if (!(node = switch_core_hash_find(globals.fifo_hash, fifo_name))) {
		node = create_node(fifo_name, 0, globals.sql_mutex);
		node->ready = 1;
	}
	switch_mutex_unlock(globals.mutex);

	name_dup = strdup(fifo_name);
	if ((p = strchr(name_dup, '@'))) { *p = '\0'; }

	sql = switch_mprintf("insert into fifo_outbound "
						 "(uuid, fifo_name, originate_string, simo_count, use_count, timeout, "
						 "lag, next_avail, expires, static, outbound_call_count, outbound_fail_count, hostname, "
						 "taking_calls, active_time, inactive_time) "
						 "values ('%q','%q','%q',%d,%d,%d,%d,%d,%ld,0,0,0,'%q',%d,%ld,0)",
						 digest, fifo_name, originate_string, simo_count, 0, timeout, lag, 0, (long)expires,
						 globals.hostname, taking_calls, (long)switch_epoch_time_now(NULL));
	switch_assert(sql);
	fifo_execute_sql_queued(&sql, SWITCH_TRUE, SWITCH_TRUE);
	free(name_dup);

	cbt.buf = outbound_count;
	cbt.len = sizeof(outbound_count);
	sql = switch_mprintf("select count(*) from fifo_outbound where fifo_name = '%q'", fifo_name);
	fifo_execute_sql_callback(globals.sql_mutex, sql, sql2str_callback, &cbt);
	node->member_count = atoi(outbound_count);
	if (node->member_count > 0) {
		node->has_outbound = 1;
	} else {
		node->has_outbound = 0;
	}
	switch_safe_free(sql);
}

SWITCH_MODULE_LOAD_FUNCTION(mod_control_load)
{
	switch_application_interface_t *app_interface;
	switch_api_interface_t *api_interface;
	switch_status_t status;

	// /* create/register custom event message type */
	// if (switch_event_reserve_subclass(CONTROL_EVENT) != SWITCH_STATUS_SUCCESS) {
	// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register subclass %s!", CONTROL_EVENT);
	// 	return SWITCH_STATUS_TERM;
	// }

	globals.pool = pool;
	switch_core_hash_init(&globals.protocol_hash);
	switch_core_hash_init(&globals.profile_hash);
	switch_core_hash_init(&globals.profile_event_hash);
	switch_core_hash_init(&globals.profile_custom_event_hash);
	switch_core_hash_init(&globals.timeout_hash);

	if ((status = load_config(0, 1)) != SWITCH_STATUS_SUCCESS) {
		switch_event_unbind(&globals.node);
		switch_event_free_subclass(FIFO_EVENT);
		switch_core_hash_destroy(&globals.fifo_hash);
		return status;
	}

	/* Subscribe to presence request events */
	if (switch_event_bind_removable(modname, SWITCH_EVENT_PRESENCE_PROBE, SWITCH_EVENT_SUBCLASS_ANY, pres_event_handler,
									NULL, &globals.node) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't subscribe to presence request events!\n");
		return SWITCH_STATUS_GENERR;
	}

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	SWITCH_ADD_APP(app_interface, "control", CONTROL_APP_DESC, "", control_app_function, CONTROL_APP_USAGE, SAF_NONE);

	SWITCH_ADD_API(api_interface, "uuid_control", CONTROL_API_DESC, control_api_function, CONTROL_API_SYNTAX);
	switch_console_set_complete("add control protocol ::control::list_protocols ::[on:off");
	switch_console_set_complete("add control profile ::control::list_profiles ::[on:off");
	switch_console_set_complete("add uuid_control ::control::list_profiles_callback");

	switch_console_add_complete_func("::control::list_protocols", list_protocols);
	switch_console_add_complete_func("::control::list_protocols_callback", list_protocols_callback);
	switch_console_add_complete_func("::control::list_profiles", list_profiles);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_control_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_control_shutdown) { return SWITCH_STATUS_SUCCESS; }

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet
 */
