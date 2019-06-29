import express from 'express';
import 'dotenv/config';


const app = express();

app.get('/', (req, res) => {
    res.send('Hello The Root Path!');
  });
  

app.listen(3000, () =>
  console.log('Example app listening on port 3000!'),
);


console.log('Hello Node.js project');
console.log(process.env.MY_SECRET);
