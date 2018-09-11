/*
 * @IMPORTANT:
 * Enter https://cloudflare.com/scc-setup in the Workers Preview ->
*/

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest (request) {
  return WorkersSCC.handleRequest(request)
}

/*
 *
 *
 *
 *
*/
