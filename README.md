Below are the steps to setting up the authentication application:

To run the executable files:
1. Navigate to ./Executables
2. Run the executable files for your system
3. (If needed) Copy the relevant source files to the correct folder if needed.
4. Browse to the address given below in your browser.
=> http://localhost:5000/
5. Voila! You can start using the application now.

To run the original files:
1. Open command prompt (Windows) / terminal (MacOS)
2. Check that node is installed. If node is not installed, you can download it here https://nodejs.org/en/download/ .
=> node -v
3. Install libraries used for the application
=> npm i express express-ejs-layouts ejs express-session mongoose passport passport-local bcryptjs connect-flash cookie-parser csurf nodemailer
4. Install nodemon to use to run server
=> npm install -g nodemon
5. Navigate to the folder containing app.js and run the server
=> nodemon app.js
6. You should get a message that the server has successfully startup.
=> Server started on port 5000
7. Browse to the address given below in your browser.
=> http://localhost:5000/
8. Voila! You can start using the application now.

Items completed:
- [x] Cookie
- [x] Input sanitization and validation
- [x] Password hashed
- [x] Password reset / forget password mechanism
- [x] CSRF prevention
- [ ] Prevention of timing attacks
- [ ] Logging
- [ ] Multi factor authentication
- [ ] Account lockout
- [ ] HTTPS
- [ ] Known password check
