output "rule_group" {
  description = "AWS WAF Rule Group which contains all rules for OWASP Top 10 protection."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule_group.owasp_top_10) > 0 ? aws_wafregional_rule_group.owasp_top_10.0 : null) : (length(aws_waf_rule_group.owasp_top_10) > 0 ? aws_waf_rule_group.owasp_top_10.0 : null )

}

output "rule01_sql_injection_rule" {
  description = "AWS WAF Rule which mitigates SQL Injection Attacks."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_01_sql_injection_rule) > 0 ? aws_wafregional_rule.owasp_01_sql_injection_rule.0 : null ) : (length(aws_waf_rule.owasp_01_sql_injection_rule) > 0 ? aws_waf_rule.owasp_01_sql_injection_rule.0 : null )
}

output "rule02_auth_token_rule" {
  description = "AWS WAF Rule which blacklists bad/hijacked JWT tokens or session IDs."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_02_auth_token_rule) > 0 ? aws_wafregional_rule.owasp_02_auth_token_rule.0 : null ) : (length(aws_waf_rule.owasp_02_auth_token_rule) > 0 ? aws_waf_rule.owasp_02_auth_token_rule.0 : null )
}

output "rule03_xss_rule" {
  description = "AWS WAF Rule which mitigates Cross Site Scripting Attacks."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_03_xss_rule) > 0 ? aws_wafregional_rule.owasp_03_xss_rule.0 : null ) : (length(aws_waf_rule.owasp_03_xss_rule) > 0 ? aws_waf_rule.owasp_03_xss_rule.0 : null )
}

output "rule04_paths_rule" {
  description = "AWS WAF Rule which mitigates Path Traversal, LFI, RFI."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_04_paths_rule) > 0 ? aws_wafregional_rule.owasp_04_paths_rule.0 : null ) : (length(aws_waf_rule.owasp_04_paths_rule) > 0 ? aws_waf_rule.owasp_04_paths_rule.0 : null )
}

output "rule06_php_insecure_rule" {
  description = "AWS WAF Rule which mitigates PHP Specific Security Misconfigurations."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_06_php_insecure_rule) > 0 ? aws_wafregional_rule.owasp_06_php_insecure_rule.0 : null ) : (length(aws_waf_rule.owasp_06_php_insecure_rule) > 0 ? aws_waf_rule.owasp_06_php_insecure_rule.0 : null )
}

output "rule07_size_restriction_rule" {
  description = "AWS WAF Rule which mitigates abnormal requests via size restrictions."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_07_size_restriction_rule) > 0 ? aws_wafregional_rule.owasp_07_size_restriction_rule.0 : null ) : (length(aws_waf_rule.owasp_07_size_restriction_rule) > 0 ? aws_waf_rule.owasp_07_size_restriction_rule.0 : null )
}

output "rule08_csrf_rule" {
  description = "AWS WAF Rule which enforces the presence of CSRF token in request header."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_08_csrf_rule) > 0 ? aws_wafregional_rule.owasp_08_csrf_rule.0 : null ) : (length(aws_waf_rule.owasp_08_csrf_rule) >0  ? aws_waf_rule.owasp_08_csrf_rule.0 : null )
}

output "rule09_server_side_include_rule" {
  description = "AWS WAF Rule which blocks request patterns for webroot objects that shouldn't be directly accessible."
  value       = lower(var.target_scope) == "regional" ? (length(aws_wafregional_rule.owasp_09_server_side_include_rule) > 0 ? aws_wafregional_rule.owasp_09_server_side_include_rule.0 : null ) : (length(aws_waf_rule.owasp_09_server_side_include_rule) >0 ? aws_waf_rule.owasp_09_server_side_include_rule.0 : null )
}
