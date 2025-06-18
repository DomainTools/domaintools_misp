ssh misp-dev "pkill -f misp-modules"
rsync -rv -e 'ssh' domaintools_misp/* misp-dev:/usr/local/lib/python3.5/dist-packages/domaintools_misp/
rsync -rv -e 'ssh' install/modules/* misp-dev:/usr/local/lib/python3.5/dist-packages/misp_modules/modules/expansion/
ssh misp-dev "sudo -u www-data misp-modules > /root/misp-module-log.log &"