import cors from 'cors';
import express from 'express';
import 'dotenv/config';


const app = express();

app.use(cors()); // all routes are extended with CORS HTTP headers. By default all routes are accessible for all domains now.

app.get('/', (req, res) => {
    res.send('Hello The Root!');
  });
  

app.listen(3000, () =>
  console.log('Example app listening on port 3000!'),
);


console.log('Hello Node.js project');
console.log(process.env.MY_SECRET);
