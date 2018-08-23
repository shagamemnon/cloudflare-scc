const Datastore = require('@google-cloud/datastore')
const MD5 = require('unique-string')
const config = require('./settings.json')
const request = require('got')
const crypto = require('crypto')
/* Adapted from https://github.com/paulja/memory-streams-js/blob/master/index.js */
const Stream = require('stream').Stream
const util = require('util')
/* https://cloud.google.com/nodejs/docs/reference/storage/1.7.x */
const Storage = require('@google-cloud/storage')
const datastore = new Datastore({ projectId: config['GOOGLE.GCLOUD_PROJECT_ID'] })

class DB {
  async save (k, data, path = MD5(config['GOOGLE.GCLOUD_PROJECT_ID'])) {
    let key = datastore.key({
      namespace: 'keys',
      path: [k, path]
    })
    let entity = {
      key: key,
      data: data
    }

    return datastore.save(entity, function (err) {
      if (!err) {
        console.log(key.path) // [ 'Company', 5669468231434240 ]
        console.log(key.namespace) // undefined
      }
    })
  }

  writeFileToBucket (filename, contents, bucketName = 'cloudflare-scc-config') {
    const storage = new Storage({ projectId: config.GOOGLE['GOOGLE_CLOUD_PROJECT'] })
    let bucket = storage.bucket(bucketName)
    try {
      console.log(`Uploading ${filename} to ${bucketName}`)
      bucket.exists(async function (err, exists) {
        if (!exists) {
          let createBucket = await bucket.create()
          bucket = createBucket[0]
        }
        const file = bucket.file(filename)
        const json = Buffer.from(JSON.stringify(contents, null, 2))
        file.save(json)
        if (err) throw console.log(err)
      })
    } catch (e) {
      console.log(e)
    }
  }

  token () {
    return crypto.createHmac('sha256', config.HMAC_SECRET_KEY).update(config.UNIQUE_LOGS_ENDPOINT).digest('base64')
  }
  // writeFileToBucket('setup.json', { name: 'frank' })

  async exists (keyword) {
    const query = datastore.createQuery(keyword)
    query.limit(1).run().then(data => {
      let entities = data[0]
      if (data) return entities[0]
    })
  }
}

util.inherits(ReadableStream, Stream.Readable)

function ReadableStream (data) {
  Stream.Readable.call(this)
  this._data = data
}

ReadableStream.prototype._read = function (n) {
  this.push(this._data)
  this._data = ''
}

ReadableStream.prototype.append = function (data) {
  this.push(data)
}

util.inherits(WritableStream, Stream.Writable)

function WritableStream (options) {
  Stream.Writable.call(this, options)
}

WritableStream.prototype.write = function (chunk, encoding, callback) {
  var ret = Stream.Writable.prototype.write.apply(this, arguments)
  if (!ret) this.emit('drain')
  return ret
}

WritableStream.prototype._write = function (chunk, encoding, callback) {
  this.write(chunk, encoding, callback)
}

WritableStream.prototype.toString = function () {
  return this.toBuffer().toString()
}

WritableStream.prototype.toBuffer = function () {
  var buffers = []
  this._writableState.buffer.forEach(function (data) {
    buffers.push(data.chunk)
  })

  return Buffer.concat(buffers)
}

WritableStream.prototype.end = function (chunk, encoding, callback) {
  var ret = Stream.Writable.prototype.end.apply(this, arguments)
  // In memory stream doesn't need to flush anything so emit `finish` right away
  // base implementation in Stream.Writable doesn't emit finish
  this.emit('finish')
  return ret
}

let db = new DB()

module.exports.callCloudflare = ({query, zone}) => {
  return request.get(`https://${config.UNIQUE_LOGS_ENDPOINT}/${zone}?token=${db.token()}&${query}`, {
    headers: {
      'User-Agent': 'Cloudflare SCC Agent'
    },
    json: true
  })
}

module.exports.DB = new DB()
module.exports.streams = {
  WritableStream: WritableStream,
  ReadableStream: ReadableStream
}
