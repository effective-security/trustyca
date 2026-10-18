# This test Root for development purposes only

```sh
gen_test_root:
	echo "*** generating test root CA"
	mkdir -p ${PROJ_DATA_DIR}/certs
	$(PROJ_ROOT)/.project/gen_certs.sh \
		--hsm-config inmem \
		--ca-config $(PROJ_ROOT)/etc/dev/certs/ca-config.bootstrap.yaml \
		--output-dir $(PROJ_ROOT)/etc/dev/certs/root \
		--csr-dir $(PROJ_ROOT)/etc/dev/certs/csr_profile \
		--csr-prefix trustyca_ \
		--out-prefix trustyca_ \
		--key-label test_root_ \
		--root-ca $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.pem \
		--root-ca-key $(PROJ_ROOT)/etc/dev/certs/root/trustyca_root.key \
		--root
	cd $(PROJ_ROOT)/etc/dev/certs/root && tar -cvzf trustyca_root.key.tar.gz trustyca_root.key
```
