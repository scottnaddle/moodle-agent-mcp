<?php
// UbionAI — Moodle web service setup (idempotent CLI script).
// Usage (from the Moodle dirroot, i.e. where config.php lives):
//   sudo -u www-data php /path/to/setup_ubionai_ws.php [--username=svc_ubionai] [--email=svc_ubionai@example.invalid]
//        [--service=ubionai] [--role=ubionai_service] [--iprestriction=203.0.113.10]
//        --token-file=/root/ubionai.token [--moodle=/var/www/moodle]
//        [--no-token]
// What it does: enables web services + REST, creates a dedicated manual-auth user, a system role
// (manager archetype capabilities + webservice/rest:use), a restricted external service with the
// functions the MCP server needs (optional mod_attendance_* skipped when the plugin is absent),
// authorises the user and issues a permanent token. The token is written to --token-file (mode 600)
// and is never printed. --token-file is required unless --no-token is given.

define('CLI_SCRIPT', true);
$opts = [];
foreach (array_slice($argv, 1) as $a) {
    if (preg_match('/^--([a-z-]+)(?:=(.*))?$/', $a, $m)) { $opts[$m[1]] = $m[2] ?? true; }
}
if (array_key_exists('token-file', $opts)
        && (!is_string($opts['token-file']) || trim($opts['token-file']) === '')) {
    fwrite(STDERR, "--token-file requires a non-empty path value\n");
    exit(2);
}
if (empty($opts['no-token']) && !array_key_exists('token-file', $opts)) {
    fwrite(STDERR, "--token-file is required (or pass --no-token)\n");
    exit(2);
}
if (empty($opts['no-token'])) {
    $tokenfile = $opts['token-file'];
    if (is_link($tokenfile)) { fwrite(STDERR, "refusing to write token to a symlink: $tokenfile\n"); exit(2); }
    $dir = dirname($tokenfile);
    if (!is_dir($dir) || !is_writable($dir)) { fwrite(STDERR, "token file directory not writable: $dir\n"); exit(2); }
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

$username = $opts['username'] ?? 'svc_ubionai';
$email = $opts['email'] ?? 'svc_ubionai@example.invalid';
$svcshort = $opts['service'] ?? 'ubionai';
$roleshort = $opts['role'] ?? 'ubionai_service';
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
if (!get_config('local_ubionai', 'version')) {
    cli_problem('local_ubionai is not installed — local_ubionai_* functions will be skipped. Install it first (see INSTALL.md).');
}

// 3. Service user.
$user = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id]);
if (!$user) {
    $u = (object)['username' => $username, 'auth' => 'manual', 'confirmed' => 1, 'mnethostid' => $CFG->mnet_localhost_id,
        'firstname' => 'UbionAI', 'lastname' => 'Bot (service)', 'email' => $email,
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
    $roleid = create_role('UbionAI service', $roleshort, 'Web service role for the UbionAI MCP server', 'manager');
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
// Allow the role to assign editingteacher/teacher/student.
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
  'core_course_update_courses','core_course_edit_module','core_course_edit_section',
  'core_courseformat_create_module','core_courseformat_update_course','core_enrol_get_enrolled_users',
  'core_user_get_users_by_field','core_files_upload','core_grades_update_grades','core_calendar_get_calendar_events',
  'gradereport_user_get_grade_items','gradereport_grader_get_users_in_report',
  'mod_assign_get_assignments','mod_assign_get_submissions','mod_assign_get_grades','mod_assign_save_grade','mod_assign_save_grades',
  'mod_quiz_get_quizzes_by_courses','mod_quiz_get_user_attempts','mod_quiz_get_attempt_review','mod_quiz_add_random_questions',
  'mod_forum_add_discussion','mod_forum_get_forum_discussions','mod_forum_get_discussion_posts',
  // optional: mod_attendance
  'mod_attendance_get_sessions','mod_attendance_get_session','mod_attendance_add_attendance','mod_attendance_add_session','mod_attendance_update_user_status',
  // local_ubionai (9)
  'local_ubionai_create_module','local_ubionai_update_module','local_ubionai_add_quiz_questions','local_ubionai_update_section',
  'local_ubionai_add_sections','local_ubionai_set_section_availability','local_ubionai_set_rubric',
  'local_ubionai_set_grade_categories','local_ubionai_create_badge',
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
} else if ($ip !== '') {
    // Re-run with --iprestriction: apply it to the existing authorisation and to the user's existing tokens too.
    $DB->set_field('external_services_users', 'iprestriction', $ip, ['externalserviceid' => $svc->id, 'userid' => $user->id]);
    $n = $DB->count_records('external_tokens', ['externalserviceid' => $svc->id, 'userid' => $user->id]);
    $DB->set_field('external_tokens', 'iprestriction', $ip, ['externalserviceid' => $svc->id, 'userid' => $user->id]);
    cli_writeln("[ok] IP restriction updated on existing authorisation and $n existing token(s)");
}
cli_writeln("[ok] $username authorised for $svcshort" . ($ip ? " (IP restriction $ip)" : ''));

// 7. Token.
if (empty($opts['no-token'])) {
    // Remove older tokens issued by this script so tokens do not accumulate.
    $tokconditions = ['externalserviceid' => (int) $svc->id, 'userid' => (int) $user->id, 'name' => 'ubionai-mcp'];
    $oldtokens = $DB->count_records('external_tokens', $tokconditions);
    if ($oldtokens) { $DB->delete_records('external_tokens', $tokconditions); }
    cli_writeln("[ok] removed $oldtokens previous ubionai-mcp token(s)");

    $tok = \core_external\util::generate_token(EXTERNAL_TOKEN_PERMANENT, \core_external\util::get_service_by_id($svc->id),
        $user->id, $sys, 0, $ip ?: '', 'ubionai-mcp');
    $tokenid = $DB->get_field('external_tokens', 'id', $tokconditions);

    // Write through a 0600 temp file in the same directory, then rename over the target so the
    // token is never written into an existing file that may have loose permissions.
    $tmpfile = @tempnam($dir, '.ubionai-token-');
    $written = false;
    if ($tmpfile !== false) {
        $written = @chmod($tmpfile, 0600);
        if ($written) { $written = @file_put_contents($tmpfile, $tok . "\n") !== false; }
        if ($written && (fileperms($tmpfile) & 0777) === 0600) {
            $written = @rename($tmpfile, $tokenfile);
        } else {
            $written = false;
        }
    }
    if (!$written) {
        if ($tmpfile !== false && file_exists($tmpfile)) { @unlink($tmpfile); }
        if ($tokenid) { $DB->delete_records('external_tokens', ['id' => $tokenid]); }
        fwrite(STDERR, "failed to write token file securely: $tokenfile\n");
        exit(2);
    }
    cli_writeln("[ok] token issued and written to $tokenfile (mode 600)");
}
cli_writeln('Done.');
