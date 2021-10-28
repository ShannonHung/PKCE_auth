My steps to when server run :
1. Open authorization URL in browser
```
http://localhost:3000/oauth2/authorize?response_type=code&client_id=pig&code_challenge=x0TUH323lFGUGY46xb-K3erPjA5XrtVHelWz1Tc6xRc=&code_challenge_method=S256&scope=read
```

2. Login with username lengleng and password 123456, and this will redirect to consent page.
3. accept the consent. This will redirect to :
```
http://127.0.0.1:9090/authorized?code=vkEKhr-ltf24KeYCGjpJGWNZDOhF0f7mLO89_PWxnX5Sxg5SZQEmy18Y6eepbIob3zmUNKTFLSyKLHg1_GB0wImzMngAqyNkgaPJz0oHHGWaTVGQFQd3XCCQAWcMvkj6
```

4. copy the code, and set the following in Postman (which follow in the video: https://www.youtube.com/watch?v=xEw5m1EV7ZY&t=1279s)
```
curl --location --request POST 'http://localhost:3000/oauth2/token?client_id=pig&code_verifier=LLrVdz2JKxBqePkp4X5NrFLb4cWl47cspdVwcVthgOk&code=vkEKhr-ltf24KeYCGjpJGWNZDOhF0f7mLO89_PWxnX5Sxg5SZQEmy18Y6eepbIob3zmUNKTFLSyKLHg1_GB0wImzMngAqyNkgaPJz0oHHGWaTVGQFQd3XCCQAWcMvkj6&grant_type=authorization_code&scope=read' \
--header 'Cookie: JSESSIONID=D5EC5CEAED017DE2148274E5B1A94A6E'
```

`Request Method` : POST
`Basic Auth` : None
`Param grant_type` : authorization_code
`Param code` : vkEKhr-ltf24KeYCGjpJGWNZDOhF0f7mLO89_PWxnX5Sxg5SZQEmy18Y6eepbIob3zmUNKTFLSyKLHg1_GB0wImzMngAqyNkgaPJz0oHHGWaTVGQFQd3XCCQAWcMvkj6
`Param client_id` : pig (I already try to include and exclude this param, result is still invalid_client)
`Param scope`: read
`Param code_verifier`：LLrVdz2JKxBqePkp4X5NrFLb4cWl47cspdVwcVthgOk
Hit Send

# TOD0O以下排序為優先順序
1. 建立resource server(PEP)，resource server 可以跟oauth進行token認證
2. 把client and user 都建立在jdbc裡面 而非inmemory
3. userDetail建立起來 可以進行使用者帳號的建立 
4. clientRegister也可以建立api來創建