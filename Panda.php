<?php

namespace AppBundle\Util;

use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class Panda
{

    private $output;
    private $curl;
    private $user_agent;
    private $url;
    private $curl_headers;
    private $response;
    private $links;

    /**
     * Panda constructor.
     * @param string $start
     * @param OutputInterface|null $output
     */
    public function __construct(string $start, OutputInterface $output = null)
    {

        /* Output Messages for Console */
        $this->output = $output;

        /* Default User Agent */
        $this->user_agent = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36';

        /* Login Url */
        $this->url = $start;

        /* Panda Endpoints */
        $this->links = array(
            'base' => 'https://sm.pandasecurity.com',
            'accounts' => 'https://accounts.pandasecurity.com',
            'alerts' => 'https://sm.pandasecurity.com/csm/device/alerts/',
            'monitor' => 'https://sm.pandasecurity.com/csm/monitor/',
            'hosts' => array(
                'accounts' => 'accounts.pandasecurity.com',
                'base' => 'www.pandacloudsecurity.com',
                'sm' => 'sm.pandasecurity.com'
            )
        );

        /* Cookie File */
        $cookieFile = 'tmp/cookie.txt';
        $fs = new Filesystem();
        if ($fs->exists($cookieFile)) {
            $fs->remove($cookieFile);
        }

        $this->curl_headers = array(
            'Cache-Control: no-cache',
            'Pragma: no-cache',
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding: gzip, deflate, br',
            'Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,pl;q=0.6,gl;q=0.5,zu;q=0.4',
            'User-Agent: ' . $this->user_agent,
            'Content-Length: 0',
            'Content-Type: application/x-www-form-urlencoded',
            'Origin: https://accounts.pandasecurity.com',
            'Upgrade-Insecure-Requests: 1',
            'Connection: keep-alive',
            'Host: TBA'
        );

        /* Initial Setup for Curl */
        $this->curl = curl_init();
        curl_setopt($this->curl, CURLOPT_USERAGENT, $this->user_agent);
        curl_setopt($this->curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($this->curl, CURLOPT_COOKIEJAR, $cookieFile);
        curl_setopt($this->curl, CURLOPT_COOKIEFILE, $cookieFile);
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, true);

        $this->displayDebug(__FUNCTION__ . ': <info>cUrl set up completed</info>');


    }

    public function login(string $user, string $pass, string $timezone = '-120;-120;-60')
    {

        /* Open the Login Page */
        curl_setopt($this->curl, CURLOPT_URL, $this->url);

        /* Get Form Url and Token */
        $crawler = new Crawler(curl_exec($this->curl));

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Loaded Login Page</info>');

        $form_url = $crawler->filter('form')->attr('action');
        $token = $crawler->filter('input[name="__RequestVerificationToken"]')->attr('value');

        /* Create POST Data Array */
        $postData = array(
            '__RequestVerificationToken' => $token,
            'Email' => $user,
            'Password' => $pass,
            'TimeZoneData' => $timezone,
        );

        /* Update Header */
        $this->resetContentAndHost($this->getContentLength($postData), $this->links['hosts']['accounts']);

        /* POST Login Data */
        curl_setopt($this->curl, CURLOPT_URL, $this->links['accounts'] . $form_url);
        curl_setopt($this->curl, CURLOPT_HEADER, $this->curl_headers);
        curl_setopt($this->curl, CURLOPT_POST, true);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postData);
        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Sent Login POST</info>');

        /* Get hidden Form Url and required params */
        $crawler = new Crawler($this->response);

        $form_hidden_url = $crawler->filter('form')->attr('action');
        $wa = $crawler->filter('input[name="wa"]')->attr('value');
        $wresult = $crawler->filter('input[name="wresult"]')->attr('value');
        $wctx = $crawler->filter('input[name="wctx"]')->attr('value');

        /* Create POST Data Array */
        $postData = array(
            'wa' => $wa,
            'wresult' => $wresult,
            'wctx' => $wctx,
        );

        /* Update Header */
        $this->resetContentAndHost($this->getContentLength($postData), $this->links['hosts']['base']);

        /* POST Hidden Login Data */
        curl_setopt($this->curl, CURLOPT_URL, $form_hidden_url);
        curl_setopt($this->curl, CURLOPT_HEADER, $this->curl_headers);
        curl_setopt($this->curl, CURLOPT_POST, true);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postData);

        /* Set the current Response */
        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Sent Intermediate Login POST</info>');

        /* Update Header */
        $this->resetContentAndHost(0, $this->links['hosts']['base']);

        /* Open the PCSM Page */
        curl_setopt($this->curl, CURLOPT_URL, $this->getPcsmLink());
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($this->curl, CURLOPT_POST, false);

        /* Set the current Response */
        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Opened PCSM Page</info>');

        $crawler = new Crawler($this->response);
        $pcsm_url = $crawler->filter('form')->attr('action');
        $saml = $crawler->filter('input[id="SamlResponse"]')->attr('value');
        $offset = $crawler->filter('input[id="offset"]')->attr('value');

        /* Create POST Data Array */
        $postData = array(
            'SamlResponse' => $saml,
            'offset' => $offset,
        );

        /* Update Header */
        $this->resetContentAndHost($this->getContentLength($postData), $this->links['hosts']['sm']);

        /* POST PCSM Login Data */
        curl_setopt($this->curl, CURLOPT_URL, $pcsm_url);
        curl_setopt($this->curl, CURLOPT_HEADER, $this->curl_headers);
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($this->curl, CURLOPT_POST, true);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postData);

        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Sent PCSM Login POST</info>');


    }

    /**
     * @return string
     */
    private function getPcsmLink()
    {
        $crawler = new Crawler($this->response);
        return str_replace('/PandaLogin', '', $this->url) . $crawler->filter('a[onclick="javascript:addAnalytics(\'PandaCloud-Home\',\'SSO\',\'PCSM_Title\'); fSleep(2000);"]')->attr('href');
    }

    /**
     * @param string $alert
     * @param string $type
     */
    public function getAlert(string $alert, string $type)
    {

        /* Open the Alert Page */
        curl_setopt($this->curl, CURLOPT_URL, $this->links['alerts'] . $alert);
        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Loaded Alert Page</info>');

        /* Get Form Url and Token */
        $crawler = new Crawler($this->response);

        try {
            $detail_page = $this->links['base'] . $crawler->filter('a[class="alert_detail_link fancybox.ajax"]')->attr('href');
        } catch (\Exception $e) {
            throw new NotFoundHttpException('No Alert found');
        }

        /* Open the Alert Page */
        curl_setopt($this->curl, CURLOPT_URL, $detail_page);
        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Loaded Alert Detail Page</info>');

        $crawler = new Crawler($this->response);
        $js = $crawler->filter('img[title="Mute Monitor for Device"]')->attr('onclick');

        /* Regex from "muteMonitor onclick" */
        preg_match_all('@muteMonitor\(\'(.*?)\', {deviceUid: \'(.*?)\', alertUid: \'(.*?)\'}\);@', $js, $matches);
        if (!is_array($matches)) {
            throw new NotFoundHttpException('IDs not found');
        }

        if (!array_key_exists(1, $matches)) {
            throw new NotFoundHttpException('Matches does not contain MonitorUid');
        }

        if (!is_array($matches[1])) {
            throw new NotFoundHttpException('Matches 1 is no array');
        }

        if (!array_key_exists(2, $matches)) {
            throw new NotFoundHttpException('Matches does not contain DeviceUid');
        }

        if (!is_array($matches[2])) {
            throw new NotFoundHttpException('Matches 2 is no array');
        }

        if (!array_key_exists(3, $matches)) {
            throw new NotFoundHttpException('Matches does not contain AlertUid');
        }

        if (!is_array($matches[3])) {
            throw new NotFoundHttpException('Matches 3 is no array');
        }

        $monitorUid = $matches[1][0];
        $deviceUid = $matches[2][0];
        $alertUid = $matches[3][0];

        /* Get endpoint from $type and create according PostData */
        /* @todo Add more mutes, this is only "resolve" and "mute Device" */
        /* @todo The "muteMonitor" endpoint does not seem to work, but it does not work at the panda site itself */
        switch ($type) {
            case 'resolve':
                $endpoint = 'resolveAlert';
                $postData = array(
                    'alertUid' => $alertUid,
                );
                break;
            case 'mute':
                $endpoint = 'muteMonitor';
                $postData = array(
                    'alertUid' => $alertUid,
                    'monitorUid' => $monitorUid,
                    'deviceUid' => $deviceUid,
                );
                break;
            default:
                throw new NotFoundHttpException('Endpoint for Panda Alert not found');
        }

        /* Complete new Header */
        $tempHeader = array(
            'Cache-Control: no-cache',
            'Pragma: no-cache',
            'Accept: */*',
            'Accept-Encoding: gzip, deflate, br',
            'Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7,pl;q=0.6,gl;q=0.5,zu;q=0.4',
            'User-Agent: ' . $this->user_agent,
            'Referer: ' . $this->links['alerts'] . $alert,
            'Content-Length: ' . $this->getContentLength($postData),
            'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            'Origin: https://sm.pandasecurity.com',
            'X-Requested-With: XMLHttpRequest',
            'Upgrade-Insecure-Requests: 1',
            'Connection: keep-alive',
            'Host: sm.pandasecurity.com'
        );

        /* POST $type Alert */
        curl_setopt($this->curl, CURLOPT_URL, $this->links['monitor'] . $endpoint);
        curl_setopt($this->curl, CURLOPT_HEADER, $tempHeader);
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($this->curl, CURLOPT_REFERER, $this->links['alerts'] . $alert);
        curl_setopt($this->curl, CURLOPT_POST, true);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postData);

        $this->response = curl_exec($this->curl);

        /* Debug */
        $this->displayDebug(__FUNCTION__ . ': <info>Sent Alert POST to endpoint ' . $endpoint . '</info>');

    }

    /**
     * @param int $contentLength
     * @param string $host
     */
    private function resetContentAndHost(int $contentLength, string $host)
    {
        $this->curl_headers[6] = 'Content-Length: ' . $contentLength;
        $this->curl_headers[11] = 'Host: ' . $host;
    }

    /**
     * @param array $postData
     * @return int
     */
    private function getContentLength(array $postData)
    {

        $postDataString = null;
        foreach ($postData as $key => $val) {
            $postDataString .= $key . '=' . urlencode($val) . '&';
        }

        return $postDataString !== null ? strlen(substr($postDataString, 0, -1)) : 0;
    }

    /**
     * @param string $message
     */
    private function displayDebug(string $message)
    {
        $this->output !== null ? $this->output->writeln($message) : null;
    }

    /**
     * Panda destructor.
     * Close curl
     */
    public function __destruct()
    {
        curl_close($this->curl);
    }


}
