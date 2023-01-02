# Web-Application-Firewall
Proof-of-Concept for a Web Application Firewall written in Prolog.

The malicious/1 predicate represents the main check for malicious requests. It checks if a given request (represented as a list of request details) is malicious by checking if it contains any of the prohibited keywords or if it has any other malicious characteristics. The prohibited keywords are defined in the prohibited/1 predicate, which specifies that the keywords sql, script, and xss are prohibited.

The long_url/1 predicate checks if a request has a long URL by checking if the url element of the request has a length greater than 200 characters. The high_param_count/1 predicate checks if a request has a high number of parameters by checking if the number of parameters in the request (excluding the method element) is greater than 10.

The malicious_ip/1 predicate checks if a request comes from a known malicious IP address by checking if the ip element of the request appears in the malicious_ip_database/1 predicate, which defines a list of known malicious IP addresses.

The violates_security_rule/1 predicate checks if a request violates any security rules specified in the security_rules database. It does this by calling the predicate specified in the security_rule/2 database and passing the request as an argument. The security_rule/2 database defines two security rules: invalid_header_value/1 and invalid_param_value/1. These predicates check if the header_value or param_value elements of the request, respectively, have a value that is considered invalid by the invalid/1 predicate. The invalid/1 predicate considers a value invalid if its length is greater than 100 characters.

The safe/1 predicate checks if a request is safe by checking if it is not malicious using the \+/1 predicate, which negates the result of the malicious/1 predicate.

Finally, the waf/1 predicate represents the WAF. It determines whether to handle or block a given request by checking if it is safe using the safe/1 predicate. If the request is safe, it is passed on to the server for handling using the handle_request/1 predicate. If it is considered malicious, the request is blocked using the block_request/1 predicate.
