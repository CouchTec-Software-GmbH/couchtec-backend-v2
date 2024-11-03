
# Pre Register
curl -X POST http://localhost/api/pre-register -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "first_name": "Linus", "last_name": "Weigand", "password": "lol"}'

# Register
curl -X POST http://localhost/api/register -H "Content-Type: application/json" -d '{"verification_code": "a3514ee4-a811-4777-8df4-c77fcf4ef359","email": "linus@couchtec.com"}'

# Login
curl -X POST http://localhost/api/login -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "password": "lol"}'



# Pre Reset Password
curl -X POST http://localhost/api/pre-reset-password -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com"}'

# Reset Password
curl -X POST http://localhost/api/reset-password -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "password": "new", "reset_password_token": "769991b4-a420-4995-847c-c461a31fc299"}'

curl -X GET https://admin:8RzuxhQ7@couchtec.linusweigand.com/viewers/f8930f730dd6ff2fcc2632ac2600eef4
