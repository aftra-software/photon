# Variables to make sure are implemented

### Global variables
Variable	Example Value  
{{BaseURL}}	https://example.com:443/foo/bar.php  
{{RootURL}}	https://example.com:443  
{{Hostname}}	example.com:443  
{{Host}}	example.com  
{{Port}}	443  
{{Path}}	/foo  
{{File}}	bar.php  
{{Scheme}}	https  

### Response-related variables
From https://github.com/projectdiscovery/nuclei/blob/dev/SYNTAX-REFERENCE.md#httprequest

`template-id` - ID of the template executed  
`template-info` - Info Block of the template executed  
`template-path` - Path of the template executed  
`host` - Host is the input to the template  
`matched` - Matched is the input which was matched upon  
`type` - Type is the type of request made  
`request` - HTTP request made from the client  
`response` - HTTP response received from server  
`status_code` - Status Code received from the Server  
`body` - HTTP response body received from server (default)  
`content_length` - HTTP Response content length  
`header`,all_headers - HTTP response headers  
`duration` - HTTP request time duration  
`all` - HTTP response body + headers  
`cookies_from_response` - HTTP response cookies in name:value format  
`headers_from_response` - HTTP response headers in name:value format  
