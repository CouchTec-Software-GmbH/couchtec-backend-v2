
# Pre Register
curl -X POST http://localhost/api/pre-register -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "first_name": "Linus", "last_name": "Weigand", "password": "lol"}'

# Register
curl -X POST http://localhost/api/register -H "Content-Type: application/json" -d '{"verification_code": "","email": "linus@couchtec.com"}'

# Login
curl -X POST http://localhost/api/login -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "password": "new"}'



# Pre Reset Password
curl -X POST http://localhost/api/pre-reset-password -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com"}'

# Pre Reset Password
curl -X POST http://localhost/api/reset-password -H "Content-Type: application/json" -d '{"email": "linus@couchtec.com", "password": "new", "reset_password_token": "16fd0481-08c9-49c7-92ab-157af89c3632"}'

curl -X https://admin:8RzuxhQ7couchtec.linusweigand.com/_utils/#database/viewers/f8930f730dd6ff2fcc2632ac2600eef4
