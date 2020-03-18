package main

const responseTpl = `
{{ $title := "SSH Authentication Succeeded" }}
{{ if .Error }}
	{{ $title = "SSH Authentication Failed" }}
{{ end }}
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
		<title>{{ $title }}</title>
	</head>
	<body class="container">
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
