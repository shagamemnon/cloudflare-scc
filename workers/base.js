/*
 *
 *
 * Enter https://cloudflare.com/scc-setup in the Browser Preview
 *
 *
 *
*/

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest (request) {
  let url = new URL(request.url)
  WorkersSCC.request = request

  switch (true) {
    case (url.href === 'https://cloudflare.com/scc-setup'):
      return WorkersSCC.establishZoneSettings()

    case (url.hostname === settings['UNIQUE_LOGS_ENDPOINT'] && WorkersSCC.HMAC('validate')):
      return WorkersSCC.pollELS()

    case url.href.includes('/dns-records'):
      return WorkersSCC.getOrigins()

    case (WorkersSCC.acceptsRoute(request.headers)):
      return WorkersSCC.handleRequest()

    default:
      return WorkersSCC.rejectRequest()
  }
  return WorkersSCC.rejectRequest()
}

/*
 *
 *
 *
 *
*/
