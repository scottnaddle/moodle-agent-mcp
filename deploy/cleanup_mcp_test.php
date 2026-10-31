<?php
// Deletes MCP test items in course 3 (assign 2/cmid 92, quiz 2/cmid 93 + its question category 6 & questions 1,2)
// and unenrols test01-05 from course 3. Run: sudo -u www-data php /opt/moodle-mcp/cleanup_mcp_test.php
define("CLI_SCRIPT",1); require "/var/www/moodle/config.php"; require_once($CFG->dirroot."/course/lib.php");
global $DB; \core\session\manager::set_user(get_admin());
foreach([92,93] as $cmid) if ($DB->record_exists("course_modules",["id"=>$cmid,"course"=>3])) { course_delete_module($cmid); echo "deleted cm $cmid\n"; }
$plugin=enrol_get_plugin("manual"); $inst=$DB->get_record("enrol",["courseid"=>3,"enrol"=>"manual"],"*",IGNORE_MULTIPLE);
foreach(["test01","test02","test03","test04","test05"] as $u){ $uid=$DB->get_field("user","id",["username"=>$u]); if($uid){$plugin->unenrol_user($inst,$uid); echo "unenrolled $u\n";} }
