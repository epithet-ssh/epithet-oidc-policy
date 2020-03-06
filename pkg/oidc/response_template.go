package oidc

const responseTpl = `
{{ $title := "Authentication Succeeded" }}
{{ if .Error }}
	{{ $title = "Authentication Failed" }}
{{ end }}
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>{{ $title }}</title>
	</head>
	<body>
		<h1>{{ $title }}</h1>
	{{ if .Error }}
		<h3>Try again after correcting the error below</h3>
		<hr>
		<dl>
			<dt>Error</dt>
			<dd>{{.Error}}</dd>
		</dl>
	{{ else }}
		<h3>Close this browser tab to continue</h3>
		<hr>
		<dl>
			<dt>Name</dt>
			<dd>{{.Name}}</dd>
			<dt>Username</dt>
			<dd>{{.Username}}</dd>
		</dl>
	{{ end }}
</body>
</html>
`
