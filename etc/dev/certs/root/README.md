# This test Root for development purposes only

```sh
gen_test_root:
	mkdir -p $(HOME)/.trustyca/certs
	rm -rf  $(HOME)/.trustyca/certs/trustyca*
	$(PROJ_ROOT)/.project/gen_certs.sh \
		--hsm-config inmem \
		--ca-config $(PROJ_ROOT)/etc/dev/certs/ca-config.bootstrap.yaml \
		--output-dir $(HOME)/.trustyca//certs \
		--csr-dir $(PROJ_ROOT)/etc/dev/certs/csr_profile \
		--csr-prefix trusty_ \
		--out-prefix trusty_ \
		--key-label test_ \
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trusty_root_ca.key \
		--root
	cd $(PROJ_ROOT)/etc/dev/certs/root && tar -cvzf trusty_root_ca.key.tar.gz trusty_root_ca.key
```
