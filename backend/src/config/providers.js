/**
 * Default provider fingerprints for subdomain takeover detection
 */
export const defaultProviders = [
  {
    name: 'GitHub Pages',
    cname: '*.github.io',
    fingerprints: [
      'There isn\'t a GitHub Pages site here.',
      'For root URLs (like http://example.com/) you must provide an index.html file',
      'Trying to publish a GitHub Pages site'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'AWS S3',
    cname: '*.s3.amazonaws.com',
    fingerprints: [
      'NoSuchBucket',
      'The specified bucket does not exist',
      'Code: NoSuchBucket'
    ],
    httpCodes: [404, 403],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Heroku',
    cname: '*.herokuapp.com',
    fingerprints: [
      'No such app',
      'There is no app configured at that hostname',
      'herokucdn.com/error-pages/no-such-app.html'
    ],
    httpCodes: [404, 410],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Azure',
    cname: '*.azurewebsites.net',
    fingerprints: [
      'Error 404 - Web app not found',
      'The resource you are looking for has been removed',
      '404 Web Site not found'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Vercel',
    cname: '*.vercel.app',
    fingerprints: [
      'The deployment could not be found on Vercel',
      '404: NOT_FOUND',
      'This page could not be found'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Netlify',
    cname: '*.netlify.app',
    fingerprints: [
      'Not Found - Request ID:',
      'Page not found',
      'Looks like you\'ve followed a broken link'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Shopify',
    cname: '*.myshopify.com',
    fingerprints: [
      'Only one step left!',
      'Sorry, this shop is currently unavailable',
      'This shop is unavailable'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Fastly',
    cname: '*.fastly.net',
    fingerprints: [
      'Fastly error: unknown domain',
      'Please check that this domain has been added to a service'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'AWS CloudFront',
    cname: '*.cloudfront.net',
    fingerprints: [
      'Bad Request',
      'ERROR: The request could not be satisfied',
      'CloudFront'
    ],
    httpCodes: [403, 404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Bitbucket',
    cname: '*.bitbucket.io',
    fingerprints: [
      'Repository not found',
      'The page you have requested does not exist'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Ghost',
    cname: '*.ghost.io',
    fingerprints: [
      'The thing you were looking for is no longer here',
      '404: Page Not Found'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Pantheon',
    cname: '*.pantheonsite.io',
    fingerprints: [
      '404 error unknown site!',
      'The gods are wise, but do not know of the site which you seek'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Tumblr',
    cname: '*.tumblr.com',
    fingerprints: [
      'There\'s nothing here',
      'Whatever you were looking for doesn\'t currently exist at this address'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'WordPress.com',
    cname: '*.wordpress.com',
    fingerprints: [
      'Do you want to register',
      'doesn\'t exist'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Zendesk',
    cname: '*.zendesk.com',
    fingerprints: [
      'Help Center Closed',
      'This help center no longer exists'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Squarespace',
    cname: '*.squarespace.com',
    fingerprints: [
      'No Such Account',
      'This domain is not configured'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Statuspage',
    cname: '*.statuspage.io',
    fingerprints: [
      'Status page doesn\'t exist',
      'You are being redirected'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Surge.sh',
    cname: '*.surge.sh',
    fingerprints: [
      'project not found',
      '404 - Not Found'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'Unbounce',
    cname: '*.unbounce.com',
    fingerprints: [
      'The requested URL was not found on this server',
      '404 - Page not found'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  },
  {
    name: 'HelpJuice',
    cname: '*.helpjuice.com',
    fingerprints: [
      'We could not find what you\'re looking for',
      'No helpdesk'
    ],
    httpCodes: [404],
    active: true,
    detectionsCount: 0
  }
];

export default defaultProviders;
