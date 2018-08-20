#!/usr/bin/env node
const { SCC } = require('./appengine/scc')
const { DB, callCloudflare } = require('./appengine/utilities')
const db = new DB()
const scc = new SCC()
const express = require('express')
const app = express()
const port = process.env.PORT || 8443
const program = require('commander')

program
  .version('0.1.0')
  .option('-r, --refresh', 'Call SCC assets endpoint')
  .option('-z, --zone [type]', 'Add the specified type of cheese [example.com]', 'example.com')
  .parse(process.argv)

if (program.refresh) {
  console.log('  - %s', program.zone)
  scc.getAssets('INSTANCE', true).then(async networks => {
    const response = await callCloudflare({ query: networks, zone: program.zone })
    response.result.forEach(obj => {
      console.log(obj.name)
    })
  })
}

app.listen(port)
console.log('\nϟϟϟ Serving on port ' + port + ' ϟϟϟ\n')
