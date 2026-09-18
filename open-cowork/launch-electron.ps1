$env:VITE_DEV_SERVER_URL = 'http://localhost:5173/'
$electron = 'D:\open-cowork\node_modules\electron\dist\electron.exe'
$main = 'D:\open-cowork\dist-electron\main\index.js'
Start-Process -FilePath $electron -ArgumentList $main, '--no-sandbox'
