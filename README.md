# panda_autologin
Login to Panda Security and resolve a given alert.
This is part of a Symfony 3.4 project but should be easily convertable. Feel free to ask for assistance.

## Use
`$panda = new Panda('https://www.pandacloudsecurity.com/PandaLogin', $output);`

If you want to use this in the console, specifiy `OutputInterface` and get some debug messages

### Login to Panda (set Cookies and Session)
`$panda->login('USERNAME','PASSWORD');`

### Resolve an alert:
`$panda->getAlert('ALERTID','resolve');`

The AlertId comes from the PCSM-Emails, they look like this: 
`The alert was last triggered at: 2018-05-22 09:22:59 CEST The alert is set to automatically resolve if not triggered for: 15 minutes The monitor https://sm.pandasecurity.com/csm/device/monitors/ALERTID is as follows:`

### Bugs
The "mute" does not seem to have any effect in the PCSM panel
