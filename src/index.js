import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import 'dotenv/config';

import routes from './routes';
import models from './models';


const app = express();

app.use(cors()); // all routes are extended with CORS HTTP headers. By default all routes are accessible for all domains now.

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use((req, res, next) => {
    req.context = {
        models,
        me: models.users[1],
    };
    next();
});

app.use('/session', routes.session);
app.use('/users', routes.user);
app.use('/messages', routes.message);


app.get('/', (req, res) => {
    return res.send('Received a GET HTTP method');
});


app.listen(process.env.PORT, () =>
    console.log(`Example app listening on port ${process.env.PORT}!`),
);


console.log('Hello Node.js project');
console.log(process.env.MY_SECRET);
