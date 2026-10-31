<?php
// Grok Bot MCP — Moodle web service setup (idempotent CLI script).
// Usage (from the Moodle dirroot, i.e. where config.php lives):
//   sudo -u www-data php /path/to/setup_grokbot_ws.php [--username=svc_grokbot] [--email=svc_grokbot@example.invalid]
//        [--service=grokbot] [--role=grokbot_service] [--iprestriction=203.0.113.10] [--token-file=/root/grokbot.token]
//        [--moodle=/var/www/moodle] [--no-token]
// What it does: enables web services + REST, creates a dedicated manual-auth user, a system role
// (manager archetype capabilities + webservice/rest:use), a restricted external service with the
// functions the MCP server needs (optional mod_attendance_* skipped when the plugin is absent),
// authorises the user and issues a permanent token. The token is written to --token-file (mode 600)
// and never printed unless no file is given.

define('CLI_SCRIPT', true);
$opts = [];
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $a, $m)) { $opts[$m[1]] = $m[2] ?? true; }
}
$dirroot = $opts['moodle'] ?? getcwd();
$cfgfile = file_exists("$dirroot/config.php") ? "$dirroot/config.php" : null;
if (!$cfgfile) { fwrite(STDERR, "config.php not found in $dirroot (use --moodle=)\n"); exit(1); }
require($cfgfile);
global $CFG, $DB;
require_once($CFG->libdir . '/clilib.php');
require_once($CFG->dirroot . '/user/lib.php');
require_once($CFG->libdir . '/externallib.php');
if (file_exists($CFG->dirroot . '/webservice/lib.php')) { require_once($CFG->dirroot . '/webservice/lib.php'); }

$username = $opts['username'] ?? 'svc_grokbot';
$email = $opts['email'] ?? 'svc_grokbot@example.invalid';
$svcshort = $opts['service'] ?? 'grokbot';
$roleshort = $opts['role'] ?? 'grokbot_service';
$ip = $opts['iprestriction'] ?? '';
$tokenfile = $opts['token-file'] ?? '';

\core\session\manager::set_user(get_admin());
$sys = context_system::instance();

// 1. Web services + REST.
set_config('enablewebservices', 1);
$protocols = array_filter(explode(',', (string)get_config('core', 'webserviceprotocols')));
if (!in_array('rest', $protocols)) { $protocols[] = 'rest'; set_config('webserviceprotocols', implode(',', $protocols)); }
cli_writeln('[ok] web services + REST enabled');

// 2. Plugin check.
if (!get_config('local_grokbot', 'version')) {
    cli_problem('local_grokbot is not installed — local_grokbot_* functions will be skipped. Install it first (see INSTALL.md).');
}

// 3. Service user.
$user = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id]);
if (!$user) {
    $u = (object)['username' => $username, 'auth' => 'manual', 'confirmed' => 1, 'mnethostid' => $CFG->mnet_localhost_id,
        'firstname' => 'Grok', 'lastname' => 'Bot (service)', 'email' => $email,
        'password' => random_string(24) . 'Aa1!', 'policyagreed' => 1];
    $uid = user_create_user($u, true, false);
    $user = $DB->get_record('user', ['id' => $uid]);
    cli_writeln("[ok] created user $username (id {$user->id}); password is random and not stored — the account is token-only");
} else {
    cli_writeln("[ok] user $username exists (id {$user->id})");
}

// 4. Role (manager archetype caps + REST use), assigned at system context.
$roleid = $DB->get_field('role', 'id', ['shortname' => $roleshort]);
if (!$roleid) {
    $roleid = create_role('Grok Bot service', $roleshort, 'Web service role for the Grok Bot MCP server', 'manager');
    foreach (get_default_capabilities('manager') as $cap => $perm) { assign_capability($cap, $perm, $roleid, $sys->id, true); }
    set_role_contextlevels($roleid, [CONTEXT_SYSTEM]);
    cli_writeln("[ok] created role $roleshort (id $roleid) from manager archetype");
}
foreach (['webservice/rest:use', 'moodle/webservice:createtoken', 'moodle/course:create', 'moodle/role:assign',
          'enrol/manual:enrol', 'moodle/course:manageactivities', 'moodle/question:add',
          'moodle/grade:managegradingforms', 'moodle/grade:manage',
          'moodle/badges:createbadge', 'moodle/badges:configurecriteria', 'moodle/badges:awardbadge'] as $cap) {
    if (get_capability_info($cap)) { assign_capability($cap, CAP_ALLOW, $roleid, $sys->id, true); }
}
// Allow the role to assign editingteacher/student (create_course enrols the bot as editingteacher).
foreach (['editingteacher', 'teacher', 'student'] as $target) {
    $tid = $DB->get_field('role', 'id', ['shortname' => $target]);
    if ($tid && !$DB->record_exists('role_allow_assign', ['roleid' => $roleid, 'allowassign' => $tid])) { core_role_set_assign_allowed($roleid, $tid); }
}
role_assign($roleid, $user->id, $sys->id);
accesslib_clear_role_cache($roleid);
cli_writeln("[ok] role $roleshort assigned to $username at system context");

// 5. External service + functions.
$functions = [
  'core_webservice_get_site_info','core_course_get_courses','core_course_get_contents','core_course_get_categories',
  'core_course_create_courses','core_course_update_courses','core_course_edit_module','core_course_edit_section',
  'core_courseformat_create_module','core_courseformat_update_course','core_enrol_get_enrolled_users',
  'core_user_get_users_by_field','core_files_upload','core_grades_update_grades','core_calendar_get_calendar_events',
  'enrol_manual_enrol_users','gradereport_user_get_grade_items','gradereport_grader_get_users_in_report',
  'mod_assign_get_assignments','mod_assign_get_submissions','mod_assign_get_grades','mod_assign_save_grade','mod_assign_save_grades',
  'mod_quiz_get_quizzes_by_courses','mod_quiz_get_user_attempts','mod_quiz_get_attempt_review','mod_quiz_add_random_questions',
  'mod_forum_add_discussion','mod_forum_get_forum_discussions','mod_forum_get_discussion_posts',
  // optional: mod_attendance
  'mod_attendance_get_sessions','mod_attendance_get_session','mod_attendance_add_attendance','mod_attendance_add_session','mod_attendance_update_user_status',
  // local_grokbot (9)
  'local_grokbot_create_module','local_grokbot_update_module','local_grokbot_add_quiz_questions','local_grokbot_update_section',
  'local_grokbot_add_sections','local_grokbot_set_section_availability','local_grokbot_set_rubric',
  'local_grokbot_set_grade_categories','local_grokbot_create_badge',
];
$svc = $DB->get_record('external_services', ['shortname' => $svcshort]);
if (!$svc) {
    $svc = (object)['name' => $svcshort, 'shortname' => $svcshort, 'enabled' => 1, 'restrictedusers' => 1,
        'downloadfiles' => 1, 'uploadfiles' => 1, 'requiredcapability' => '', 'component' => null, 'timecreated' => time()];
    $svc->id = $DB->insert_record('external_services', $svc);
    cli_writeln("[ok] created external service $svcshort (id {$svc->id})");
} else {
    $DB->update_record('external_services', (object)['id' => $svc->id, 'enabled' => 1, 'restrictedusers' => 1, 'downloadfiles' => 1, 'uploadfiles' => 1]);
}
$added = 0; $skipped = [];
foreach ($functions as $fn) {
    if (!$DB->record_exists('external_functions', ['name' => $fn])) { $skipped[] = $fn; continue; }
    if (!$DB->record_exists('external_services_functions', ['externalserviceid' => $svc->id, 'functionname' => $fn])) {
        $DB->insert_record('external_services_functions', (object)['externalserviceid' => $svc->id, 'functionname' => $fn]);
        $added++;
    }
}
$total = $DB->count_records('external_services_functions', ['externalserviceid' => $svc->id]);
cli_writeln("[ok] service functions: $total total ($added added)");
if ($skipped) { cli_writeln('[skip] not available on this site (optional plugin missing?): ' . implode(', ', $skipped)); }

// 6. Authorise user.
if (!$DB->record_exists('external_services_users', ['externalserviceid' => $svc->id, 'userid' => $user->id])) {
    $DB->insert_record('external_services_users', (object)['externalserviceid' => $svc->id, 'userid' => $user->id,
        'iprestriction' => $ip ?: null, 'validuntil' => 0, 'timecreated' => time()]);
}
cli_writeln("[ok] $username authorised for $svcshort" . ($ip ? " (IP restriction $ip)" : ''));

// 7. Token.
if (empty($opts['no-token'])) {
    $tok = \core_external\util::generate_token(EXTERNAL_TOKEN_PERMANENT, \core_external\util::get_service_by_id($svc->id),
        $user->id, $sys, 0, $ip ?: '', 'grokbot-mcp');
    if ($tokenfile) {
        $old = umask(0077); file_put_contents($tokenfile, $tok . "\n"); umask($old); chmod($tokenfile, 0600);
        cli_writeln("[ok] token issued and written to $tokenfile (mode 600)");
    } else {
        cli_writeln('[ok] token issued (no --token-file given, printing once):');
        cli_writeln($tok);
    }
}
cli_writeln('Done.');
