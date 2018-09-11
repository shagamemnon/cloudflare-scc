/*
 * @IMPORTANT:
 * Enter https://cloudflare.com/scc-setup in the Workers Preview ->
*/

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest (request) {
  if (request.headers.get('Host').match(SETTINGS.UNIQUE_LOGS_ENDPOINT)) {
    return WorkersSCC.handleRequest(request)
  }
  return fetch(request)
}

/*
 *
 *
 *
 *
*/
