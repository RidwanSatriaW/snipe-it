

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <form action="{{ url('/loginApi') }}" method="post">
        <input type="hidden" name="_token" value="{{ csrf_token() }}" />
        Email <input type="text" name="email">    
        Password <input type="password" name="password">    
        <input type="submit">
    </form>
</body>
</html>