const https = require('https');

async function httpsGet(hostname, path, headers) {
  return new Promise(async (resolve, reject) => {

    const options = {
      hostname: hostname,
      path: path,
      port: 443,
      method: 'GET',
      headers: headers
    };

    let body = [];

    const req = https.request(options, res => {
      res.on('data', chunk => body.push(chunk));
      res.on('end', () => {
        const data = Buffer.concat(body).toString();
        resolve(data);
      });
    });
    req.on('error', e => {
      reject(e);
    });
    req.end();

  });

}

result = httpsGet("www.baidu.com", "/", "");
result.then(function (data) {
　　console.log(data)
},function (err) {
   consoel.log('https request failed',err)
})