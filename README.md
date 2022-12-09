golang oauth2 server，OAuth2 非标准实现   

快速开始:
```go
package main

import "github.com/cro4k/oauth2"

func main(){
    ex := example.NewExample()
    ex.Serve(":8000")
}
```
浏览器访问：
```
http://127.0.0.1:8000/authorize?client_id=1000&redirect=http%3A%2F%2F127.0.0.1%3A8000%2Fexample%2Fcallback&sid=123456&state=hello+world
```

授权流程：
