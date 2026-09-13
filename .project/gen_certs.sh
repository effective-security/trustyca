#!/bin/bash
set -e
#
# gen_certs.sh
#   --output-dir {dir}         - specifies output folder
#   --output-prefix {prefix}   - specifies prefix for output files
#   --csr-dir {dir}         - specifies folder with CSR templates
#   --csr-prefix {prefix}   - specifies prefix for csr files
#   --key-label {prefix}    - specifies prefix for key label, by default empty
#   --hsm-confg             - specifies HSM provider file
#   --crypto                - specifies additional HSM provider file
#   --ca-config             - specifies CA configuration file
#   --root-ca {cert}        - specifies root CA certificate
#   --root-ca-key {key}     - specifies root CA key
#   --root                  - specifies if Root CA certificate and key should be generated
#   --ca1                   - specifies if Level 1 CA certificate and key should be generated
#   --ca2                   - specifies if Level 2 CA certificate and key should be generated
#   --server                - specifies if server TLS certificate and key should be generated
#   --client                - specifies if client certificate and key should be generated
#   --jobs                  - specifies if jobs certificate and key should be generated
#   --peer                  - specifies if peer certificate and key should be generated
#   --bundle                - specifies if Int CA Bundle should be created
#   --san                   - specifies SAN for server and peer certs
#   --force                 - specifies to force issuing the cert even if it exists
#   --verbose               - specifies to enable verbose logs
#

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -o|--output-dir|--out-dir)
    OUT_DIR="$2"
    shift # past argument
    shift # past value
    ;;
    --output-prefix|--out-prefix)
    OUT_PREFIX="$2"
    shift # past argument
    shift # past value
    ;;
    -o|--csr-dir)
    CSR_DIR="$2"
    shift # past argument
    shift # past value
    ;;
    --csr-prefix)
    CSR_PREFIX="$2"
    shift # past argument
    shift # past value
    ;;
    -l|--key-label)
    KEY_LABEL="$2"
    shift # past argument
    shift # past value
    ;;
    -c|--ca-config)
    CA_CONFIG="$2"
    shift # past argument
    shift # past value
    ;;
    --hsm-config)
    HSM_CONFIG="$2"
    shift # past argument
    shift # past value
    ;;
    --crypto)
    CRYPTO_PROV="--crypto=$2"
    shift # past argument
    shift # past value
    ;;
    --root-ca)
    ROOT_CA_CERT="$2"
    shift # past argument
    shift # past value
    ;;
    --root-ca-key)
    ROOT_CA_KEY="$2"
    shift # past argument
    shift # past value
    ;;
    --root)
    ROOTCA=YES
    shift # past argument
    ;;
    --ca1)
    CA1=YES
    shift # past argument
    ;;
    --ca2)
    CA2=YES
    shift # past argument
    ;;
    --server)
    SERVER=YES
    shift # past argument
    ;;
    --admin)
    ADMIN=YES
    shift # past argument
    ;;
    --client)
    CLIENT=YES
    shift # past argument
    ;;
    --jobs)
    JOBS=YES
    shift # past argument
    ;;
    --peers|--peer)
    PEERS=YES
    shift # past argument
    ;;
    --force)
    FORCE=YES
    shift # past argument
    ;;
    --bundle)
    BUNDLE=YES
    shift # past argument
    ;;
    --san|--SAN)
    SAN="$2"
    shift # past argument
    shift # past value
    ;;
    --verbose)
    FLAGS="-D"
    shift # past argument
    ;;
    *)
    echo "invalid flag $key: use --help to see the option"
    exit 1
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

[ -z "$OUT_DIR" ] &&  echo "Specify --output-dir" && exit 1
[ -z "$CSR_DIR" ] &&  echo "Specify --csr-dir" && exit 1
[ -z "$CA_CONFIG" ] && echo "Specify --ca-config" && exit 1
[ -z "$HSM_CONFIG" ] && echo "Specify --hsm-config" && exit 1
[ -z "$ROOT_CA_CERT" ] && ROOT_CA_CERT=${OUT_DIR}/${OUT_PREFIX}root_ca.pem
[ -z "$ROOT_CA_KEY" ] && ROOT_CA_KEY=${OUT_DIR}/${OUT_PREFIX}root_ca.key
[ -z "$SAN" ] && SAN=127.0.0.1

HOSTNAME=`hostname`
CABUNDLE=${OUT_DIR}/${OUT_PREFIX}cabundle.pem

echo "FLAGS        = ${FLAGS}"
echo "OUT_DIR      = ${OUT_DIR}"
echo "OUT_PREFIX   = ${OUT_PREFIX}"
echo "CSR_DIR      = ${CSR_DIR}"
echo "CSR_PREFIX   = ${OUT_PREFIX}"
echo "CA_CONFIG    = ${CA_CONFIG}"
echo "HSM_CONFIG   = ${HSM_CONFIG}"
echo "CRYPTO_PROV  = ${CRYPTO_PROV}"
echo "KEY_LABEL    = ${KEY_LABEL}"
echo "BUNDLE       = ${BUNDLE}"
echo "FORCE        = ${FORCE}"
echo "SAN          = ${SAN}"
echo "ROOT_CA_CERT = ${ROOT_CA_CERT}"
echo "ROOT_CA_KEY  = ${ROOT_CA_KEY}"
echo "CABUNDLE     = ${CABUNDLE}"

if [[ "$FLAGS" == "-D" ]]; then echo "*** hsm-tool "
    hsm-tool --version; 
fi

if [[ "$ROOTCA" == "YES" && ("$FORCE" == "YES" || ! -f ${ROOT_CA_KEY}) ]]; then echo "*** generating ${ROOT_CA_CERT/.pem/''}"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG} ${CRYPTO_PROV} \
        csr gen-cert --self-sign \
        --ca-config ${CA_CONFIG} \
        --profile ROOT \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}root_ca.yaml \
        --key-label "${KEY_LABEL}${OUT_PREFIX}root_ca*" \
        --output ${ROOT_CA_CERT/.pem/''}
fi

if [[ "$CA1" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}l1_ca.key) ]]; then
    echo "*** generating L1 CA cert: ${OUT_DIR}/${OUT_PREFIX}l1_ca.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG} ${CRYPTO_PROV} \
        csr gen-cert \
        --ca-config ${CA_CONFIG} \
        --profile L1_CA \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}l1_ca.yaml \
        --key-label "${KEY_LABEL}${OUT_PREFIX}l1_ca*" \
        --ca-cert ${ROOT_CA_CERT} \
        --ca-key ${ROOT_CA_KEY} \
        --output ${OUT_DIR}/${OUT_PREFIX}l1_ca
fi

if [[ "$CA2" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}l2_ca.key) ]]; then
    echo "*** generating L2 CA cert: ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem"
    hsm-tool ${FLAGS} \
        --cfg=${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert \
        --ca-config ${CA_CONFIG} \
        --profile L2_CA \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}l2_ca.yaml \
        --key-label "${KEY_LABEL}${OUT_PREFIX}l2_ca*" \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l1_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l1_ca.key \
        --output ${OUT_DIR}/${OUT_PREFIX}l2_ca
fi

if [[ "$BUNDLE" == "YES" && ("$FORCE" == "YES" || ! -f ${CABUNDLE}) ]]; then
    echo "*** CA bundle: ${CABUNDLE}"
    if [[ -f ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem ]]; then
        cat ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem > ${CABUNDLE}
    fi
    if [[ -f ${OUT_DIR}/${OUT_PREFIX}l1_ca.pem ]]; then
        cat ${OUT_DIR}/${OUT_PREFIX}l1_ca.pem >> ${CABUNDLE}
    fi
fi

if [[ "$ADMIN" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}admin.key) ]]; then
    echo "*** generating admin cert: ${OUT_DIR}/${OUT_PREFIX}admin.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert --plain-key \
        --ca-config=${CA_CONFIG} \
        --profile client \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l2_ca.key \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}admin.yaml \
        --key-label "${KEY_LABEL}${OUT_PREFIX}admin*" \
        --output ${OUT_DIR}/${OUT_PREFIX}admin

    cat ${CABUNDLE} >> ${OUT_DIR}/${OUT_PREFIX}admin.pem
fi

if [[ "$SERVER" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}server.key) ]]; then
    echo "*** generating server cert: ${OUT_DIR}/${OUT_PREFIX}server.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert --plain-key \
        --ca-config ${CA_CONFIG} \
        --profile server \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l2_ca.key \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}server.yaml \
        --san localhost,${SAN},${HOSTNAME} \
        --key-label="${KEY_LABEL}${OUT_PREFIX}server*" \
        --output ${OUT_DIR}/${OUT_PREFIX}server

    cat ${CABUNDLE} >> ${OUT_DIR}/${OUT_PREFIX}server.pem
fi

if [[ "$CLIENT" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}client.key) ]]; then
    echo "*** generating client cert: ${OUT_DIR}/${OUT_PREFIX}client.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert --plain-key \
        --ca-config ${CA_CONFIG} \
        --profile client \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l2_ca.key \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}client.yaml \
        --san spiffe://trustyca/client \
        --key-label "${KEY_LABEL}${OUT_PREFIX}client*" \
        --output ${OUT_DIR}/${OUT_PREFIX}client

    cat ${CABUNDLE} >> ${OUT_DIR}/${OUT_PREFIX}client.pem
fi

if [[ "$JOBS" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}jobs.key) ]]; then
    echo "*** generating jobs cert: ${OUT_DIR}/${OUT_PREFIX}jobs.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert --plain-key \
        --ca-config ${CA_CONFIG} \
        --profile client \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l2_ca.key \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}jobs.yaml \
        --san spiffe://trustyca/jobs \
        --key-label "${KEY_LABEL}${OUT_PREFIX}jobs*" \
        --output ${OUT_DIR}/${OUT_PREFIX}jobs

    cat ${CABUNDLE} >> ${OUT_DIR}/${OUT_PREFIX}jobs.pem
fi


if [[ "$PEERS" == "YES" && ("$FORCE" == "YES" || ! -f ${OUT_DIR}/${OUT_PREFIX}peer.key) ]]; then
    echo "*** generating peer cert: ${OUT_DIR}/${OUT_PREFIX}peer.pem"
    hsm-tool ${FLAGS} \
        --cfg ${HSM_CONFIG}  ${CRYPTO_PROV} \
        csr gen-cert --plain-key \
        --ca-config ${CA_CONFIG} \
        --profile peer \
        --ca-cert ${OUT_DIR}/${OUT_PREFIX}l2_ca.pem \
        --ca-key ${OUT_DIR}/${OUT_PREFIX}l2_ca.key \
        --csr-profile ${CSR_DIR}/${CSR_PREFIX}peer.yaml \
        --san localhost,${SAN},${HOSTNAME},spiffe://trustyca/peer \
        --key-label "${KEY_LABEL}${OUT_PREFIX}peer*" \
        --output ${OUT_DIR}/${OUT_PREFIX}peer

    cat ${CABUNDLE} >> ${OUT_DIR}/${OUT_PREFIX}peer.pem
fi

chmod 400 ${OUT_DIR}/*.key
chmod 644 ${OUT_DIR}/*.pem
