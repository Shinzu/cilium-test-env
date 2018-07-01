#! /usr/bin/env bash
# set static ip in vm adopted from https://github.com/fivestars/docker-machine-ipconfig

set -o errexit
set -o pipefail
set -o nounset
#IFS=$'\n\t'

NODES=("master" "worker01" "worker02" "worker03")
K8S_VERSION="v1.10.3"
ISO_VERSION="v0.28.0_4.14.51"
MASTER_ROLE="MASTER"
MASTER_MEMORY="8192"
MASTER_CPU="2"
MASTER_DISKSIZE="15000"
MASTER_IP="192.168.88.50"
MASTER_IP_NAT="10.0.2.50"
WORKER01_ROLE="WORKER"
WORKER02_ROLE="WORKER"
WORKER03_ROLE="WORKER"
WORKER_MEMORY="2048"
WORKER_CPU="1"
WORKER_DISKSIZE="10000"
WORKER01_IP="192.168.88.51"
WORKER01_IP_NAT="10.0.2.51"
WORKER02_IP="192.168.88.52"
WORKER02_IP_NAT="10.0.2.52"
WORKER03_IP="192.168.88.53"
WORKER03_IP_NAT="10.0.2.53"
GATEWAY_NAT="10.0.2.2"
SSH_USER="docker"
SSH_OPTIONS="ssh -o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -l docker -i"
SCP_OPTIONS="scp -o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i"
HOME_DIR="/C/Users/shinz"
FILE_ROOT="$(pwd)/static_files"
ISO_ROOT="$(pwd)/iso/$ISO_VERSION"
BIN_ROOT="$(pwd)/binaries/$K8S_VERSION"
BINARIES=("kubeadm" "kubelet")
PKI_ROOT="$(pwd)/PKI"
CA_ROOT="$(pwd)/PKI/docker_ca"
B2D_DIR="/var/lib/boot2docker"
DOCKER_MACHINE="docker-machine"
#VBOX_MANAGE="VBoxManage"
KUBECTL="kubectl"
DEPLOY_CILIUM="true"

# prints colored text https://stackoverflow.com/questions/5412761/using-colors-with-printf
# fancy print
fp() {

  if [ "$2" == "info" ]; then
    COLOR="96m"
  elif [ "$2" == "success" ]; then
    COLOR="92m"
  elif [ "$2" == "warning" ]; then
    COLOR="93m"
  elif [ "$2" == "danger" ]; then
    COLOR="91m"
  else #default color
    COLOR="0m"
  fi

  STARTCOLOR="\e[$COLOR"
  ENDCOLOR="\e[0m"

  printf "$STARTCOLOR%b$ENDCOLOR\n" "$1"
}

# https://unix.stackexchange.com/questions/412868/bash-reverse-an-array
reverse() {
  # first argument is the array to reverse
  # second is the output array
  declare -n ARR="$1" REV="$2"
  for i in "${ARR[@]}"; do
    REV=("$i" "${REV[@]}")
  done
}

convert_path() {
  declare -n VAR="$1"
  case $OSTYPE in
    msys*)
      VAR=$(echo "/$VAR" | sed 's/\\/\//g' | sed 's/://')
      ;;
    *) ;;
  esac
}

deploy_node() {
  NODE="$1"
  NODE_IP="${NODE^^}_IP"
  NODE_IP="${!NODE_IP}"
  NODE_IP_NAT="${NODE^^}_IP_NAT"
  NODE_IP_NAT="${!NODE_IP_NAT}"
  NODE_ROLE="${NODE^^}_ROLE"
  NODE_ROLE="${!NODE_ROLE}"

  case $NODE_ROLE in
    MASTER)
      MEMORY=$MASTER_MEMORY
      CPU=$MASTER_CPU
      DISKSIZE=$MASTER_DISKSIZE
      ;;
    WORKER)
      MEMORY=$WORKER_MEMORY
      CPU=$WORKER_CPU
      DISKSIZE=$WORKER_DISKSIZE
      ;;
  esac

  #$DOCKER_MACHINE create -d "virtualbox" \
  #  --virtualbox-boot2docker-url "file:/$ISO_ROOT/minikube-$ISO_VERSION.iso" \
  #  --virtualbox-cpu-count "$CPU" \
  #  --virtualbox-memory "$MEMORY" \
  #  --virtualbox-disk-size "$DISKSIZE" \
  #  --virtualbox-hostonly-nictype "virtio" \
  #  --virtualbox-nat-nictype "virtio" \
  #  "$NODE" || :
  $DOCKER_MACHINE create -d "vmware" \
    --vmware-boot2docker-url "file:/$ISO_ROOT/minikube-$ISO_VERSION.iso" \
    --vmware-cpu-count "$CPU" \
    --vmware-memory-size "$MEMORY" \
    --vmware-disk-size "$DISKSIZE" \
    "$NODE" || :
  #  --vmware-no-share \

  NODE_SSHKEY=$($DOCKER_MACHINE inspect "$NODE" -f '{{.Driver.SSHKeyPath}}')

  convert_path NODE_SSHKEY

  DHCP_IP=$($DOCKER_MACHINE ip "$NODE")
  SSH_COMMAND="$SSH_OPTIONS $NODE_SSHKEY"
  SCP_COMMAND="$SCP_OPTIONS $NODE_SSHKEY"

  # set natnetwork on internal network if
  #$VBOX_MANAGE controlvm "$NODE" nic1 natnetwork "NatNetwork"
  # set portwarding
  # $VBOX_MANAGE natnetwork modify --netname "NatNetwork" --port-forward-4 "master:tcp:[]:10050:[${NODE_IP_NAT}]:22"
  # start natnetwork
  # VBoxManage.exe natnetwork start --netname NatNetwork

  while true; do
    MOUNT_RDY=$($SSH_COMMAND "$DHCP_IP" "mount -l | grep boot2docker | grep /dev/sda1" || :)
    if [[ ! -z $MOUNT_RDY ]]; then
      break
    fi
    sleep 5
  done

  # create directory structure
  $SSH_COMMAND "$DHCP_IP" "sudo mkdir -p $B2D_DIR/etc/systemd/system && \
            sudo chown docker:docker $B2D_DIR/etc/systemd/system && \
            sudo mkdir -p $B2D_DIR/etc/systemd/network && \
            sudo chown docker:docker $B2D_DIR/etc/systemd/network && \
            sudo mkdir -p $B2D_DIR/etc/systemd/system/kubelet.service.d && \
            sudo chown docker:docker $B2D_DIR/etc/systemd/system/kubelet.service.d && \
            sudo mkdir -p $B2D_DIR/etc/sysconfig && \
            sudo chown docker:docker $B2D_DIR/etc/sysconfig && \
            sudo mkdir -p $B2D_DIR/etc/docker && \
            sudo chown docker:docker $B2D_DIR/etc/docker && \
            sudo mkdir -p $B2D_DIR/usr/bin && \
            sudo chown docker:docker $B2D_DIR/usr/bin && \
            sudo mkdir -p $B2D_DIR/etc/kubernetes"
  # move certificate
  # ca created with:
  # easypki.exe --root PKI create --filename docker_ca --ca "Shinzu Org Certificate Authority"
  # certs created with:
  # easypki.exe --root PKI create --ca-name docker_ca --dns master --ip 127.0.0.1 --ip 192.168.99.50 master
  $SCP_COMMAND "$CA_ROOT/certs/$NODE.crt" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/server.pem"
  $SCP_COMMAND "$CA_ROOT/certs/docker_ca.crt" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/ca.pem"
  $SCP_COMMAND "$CA_ROOT/keys/$NODE.key" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/server-key.pem"
  # move/create servie/binary files and bootlocal
  $SCP_COMMAND "$FILE_ROOT/kubelet.service" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/systemd/system"
  $SCP_COMMAND "$FILE_ROOT/docker.service" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/systemd/system"
  $SCP_COMMAND "$FILE_ROOT/crio.minikube" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/sysconfig"
  $SCP_COMMAND "$BIN_ROOT/kubelet" "$SSH_USER@$DHCP_IP:$B2D_DIR/usr/bin"
  $SCP_COMMAND "$BIN_ROOT/kubeadm" "$SSH_USER@$DHCP_IP:$B2D_DIR/usr/bin"

  if [ "$NODE_ROLE" == "MASTER" ]; then
    cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee $B2D_DIR/etc/systemd/system/kubelet.service.d/10-kubeadm.conf >/dev/null"
[Service]
ExecStart=
ExecStart=/usr/bin/kubelet --client-ca-file=/var/lib/localkube/certs/ca.crt \
    --cgroup-driver=cgroupfs \
    --hostname-override=$NODE \
    --allow-privileged=true \
    --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
    --pod-manifest-path=/etc/kubernetes/manifests \
    --cluster-dns=10.96.0.10 \
    --cluster-domain=cluster.local \
    --cadvisor-port=0 \
    --fail-swap-on=false \
    --kubeconfig=/etc/kubernetes/kubelet.conf \
    --network-plugin=cni \
    --feature-gates=CustomResourceValidation=true

[Install]
Wants=docker.socket
WantedBy=multi-user.target
EOF
  else
    cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee $B2D_DIR/etc/systemd/system/kubelet.service.d/10-kubeadm.conf >/dev/null"
[Service]
ExecStart=
ExecStart=/usr/bin/kubelet --client-ca-file=/etc/kubernetes/pki/ca.crt \
    --cgroup-driver=cgroupfs \
    --hostname-override=$NODE \
    --allow-privileged=true \
    --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
    --pod-manifest-path=/etc/kubernetes/manifests \
    --cluster-dns=10.96.0.10 \
    --cluster-domain=cluster.local \
    --cadvisor-port=0 \
    --fail-swap-on=false \
    --kubeconfig=/etc/kubernetes/kubelet.conf \
    --network-plugin=cni \
    --feature-gates=CustomResourceValidation=true \
    --node-labels 'node-role.kubernetes.io/node='

[Install]
Wants=docker.socket
WantedBy=multi-user.target
EOF
  fi

  cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee $B2D_DIR/etc/systemd/network/10-eth0.network >/dev/null"
[Match]
Name=eth0

[Network]
DNS=$GATEWAY_NAT
Address=$NODE_IP_NAT/24
Gateway=$GATEWAY_NAT
EOF

  cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee $B2D_DIR/etc/systemd/network/10-eth1.network >/dev/null"
[Match]
Name=eth1

[Network]
Address=$NODE_IP/24
EOF
  cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee -a $B2D_DIR/bootlocal.sh >/dev/null && sudo chmod u+x $B2D_DIR/bootlocal.sh"
#!/bin/sh

# wait until natnetwork is up
while true; do
if ip a | grep -q '10.0.2.' ; then
  break
fi
sleep 1
done

# wait a bit so that docker-machine recognize that the node is up in case of e restart
sleep 5

# flush dhcp ip
ip addr flush dev eth1
ip addr flush dev eth0

# set hostname
/bin/hostname $NODE
sed -i 's/minikube/$NODE/g' /etc/hosts

# disable swap
#swapoff -a

# link services/binaries
ln -s $B2D_DIR/etc/docker/server.pem /etc/docker/server.pem
ln -s $B2D_DIR/etc/docker/server-key.pem /etc/docker/server-key.pem
ln -s $B2D_DIR/etc/docker/ca.pem /etc/docker/ca.pem
ln -s $B2D_DIR/etc/sysconfig/crio.minikube /etc/sysconfig/crio.minikube
ln -s $B2D_DIR/etc/systemd/system/kubelet.service.d /etc/systemd/system/kubelet.service.d
ln -s $B2D_DIR/etc/systemd/system/kubelet.service /etc/systemd/system/kubelet.service
ln -s $B2D_DIR/etc/systemd/system/docker.service /etc/systemd/system/docker.service
ln -sf $B2D_DIR/etc/systemd/network/10-eth0.network /etc/systemd/network/10-eth0.network
ln -sf $B2D_DIR/etc/systemd/network/10-eth1.network /etc/systemd/network/10-eth1.network
ln -s $B2D_DIR/etc/kubernetes /etc/kubernetes
chmod +x $B2D_DIR/usr/bin/kubelet
chmod +x $B2D_DIR/usr/bin/kubeadm
ln -s $B2D_DIR/usr/bin/kubelet /usr/bin/kubelet
ln -s $B2D_DIR/usr/bin/kubeadm /usr/bin/kubeadm
sed -i 's/mkdir/\/bin\/mkdir/g' /lib/systemd/system/crio-shutdown.service
mkdir -p /mnt/sda1/var/lib/crio
mkdir -p /var/lib/crio
mount --bind /mnt/sda1/var/lib/crio /var/lib/crio
mkdir -p /data/storage
mkdir -p /data/asciinema
/usr/bin/vmhgfs-fuse .host:/Storage/$NODE /data/storage -o subtype=vmhgfs-fuse,allow_other
/usr/bin/vmhgfs-fuse .host:/Storage/asciinema /data/asciinema -o subtype=vmhgfs-fuse,allow_other

# mount bpffs
mount bpffs /sys/fs/bpf -t bpf

# reload/start services
systemctl daemon-reload
systemctl enable docker.service
systemctl enable kubelet.service
(sleep 10 ; systemctl restart systemd-networkd ; systemctl restart crio.service ; systemctl start docker.service ; systemctl start kubelet.service) &
EOF

  $SSH_COMMAND "$DHCP_IP" "sudo $B2D_DIR/bootlocal.sh > /tmp/bootlocal.log 2>&1 &" || :
  # write kubeadm conf on master
  if [ "$NODE_ROLE" == "MASTER" ]; then
    while true; do
      fp "Trying connection to new static ip" "info"
      if $SSH_COMMAND "$NODE_IP_NAT" "exit"; then
        break
      fi
      sleep 1
    done
    cat <<EOF | $SSH_COMMAND "$NODE_IP_NAT" "sudo tee /var/lib/kubeadm.yaml >/dev/null"
apiVersion: kubeadm.k8s.io/v1alpha1
kind: MasterConfiguration
api:
  advertiseAddress: $NODE_IP_NAT
  bindPort: 8443
kubernetesVersion: $K8S_VERSION
featureGates:
  CoreDNS: true
certificatesDir: /var/lib/localkube/certs/
networking:
  serviceSubnet: 10.96.0.0/12
etcd:
  dataDir: /data
  ServerCertSANs: [$NODE_IP, $NODE_IP_NAT]
  extraArgs:
    listen-client-urls: "https://127.0.0.1:2379,https://$NODE_IP_NAT:2379"
    advertise-client-urls: "https://127.0.0.1:2379,https://$NODE_IP_NAT:2379"
nodeName: $NODE
apiServerExtraArgs:
  admission-control: "Initializers,NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota"
  feature-gates: "CustomResourceValidation=true"
controllerManagerExtraArgs:
  allocate-node-cidrs: "true"
  cluster-cidr: "10.2.0.0/16"
  feature-gates: "CustomResourceValidation=true"
schedulerExtraArgs:
  feature-gates: "CustomResourceValidation=true"
apiServerCertSANs:
- "$NODE_IP"
- "127.0.0.1"
EOF

    # bootstrap k8s with kubeadm
    $SSH_COMMAND "$NODE_IP_NAT" "sudo /usr/bin/kubeadm init --config /var/lib/kubeadm.yaml \
                --ignore-preflight-errors=DirAvailable--etc-kubernetes-manifests \
                --ignore-preflight-errors=DirAvailable--data \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-scheduler.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-apiserver.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-controller-manager.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-etcd.yaml \
                --ignore-preflight-errors=Swap \
                --ignore-preflight-errors=CRI" | tee "$(pwd)"/kubeadm.log

    $SSH_COMMAND "$NODE_IP_NAT" "sudo cat /etc/kubernetes/admin.conf" >$HOME_DIR/.kube/config
    sed -i "s/$NODE_IP_NAT:8443/127.0.0.1:18443/" $HOME_DIR/.kube/config
  else
    while true; do
      fp "Trying connection to new static ip" "info"
      if $SSH_COMMAND "$NODE_IP_NAT" "exit"; then
        break
      fi
      sleep 1
    done
    #fp "You must join this Worker Node with the command provided with the Outout of kubeadm from the master node" "warning"
    KUBEADM_JOIN=$(grep "kubeadm join" "$(pwd)"/kubeadm.log | sed -e 's/^[[:space:]]*//')
    fp "Joining cluster" "info"
    $SSH_COMMAND "$NODE_IP_NAT" "sudo $KUBEADM_JOIN \
                --ignore-preflight-errors=DirAvailable--etc-kubernetes-manifests \
                --ignore-preflight-errors=DirAvailable--data \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-scheduler.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-apiserver.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-controller-manager.yaml \
                --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-etcd.yaml \
                --ignore-preflight-errors=Swap \
                --ignore-preflight-errors=CRI"
  fi
}

OPERATION=${1:-}
NODE_NAME=${2:-}
case $OPERATION in
  create)
    # test/download iso and binaries
    if [[ ! -d "$ISO_ROOT" ]]; then
      mkdir -p "$(pwd)/iso/$ISO_VERSION"
    fi

    if [[ ! -f "$ISO_ROOT/minikube-$ISO_VERSION.iso" ]]; then
      curl "https://storage.googleapis.com/minikube/iso/minikube-$ISO_VERSION.iso" -o "$ISO_ROOT/minikube-$ISO_VERSION.iso"
    fi

    if [[ ! -d "$BIN_ROOT" ]]; then
      mkdir -p "$(pwd)/binaries/$K8S_VERSION"
    fi

    for BINARY in "${BINARIES[@]}"; do
      if [[ ! -f "$BIN_ROOT/$BINARY" ]]; then
        curl "https://storage.googleapis.com/kubernetes-release/release/$K8S_VERSION/bin/linux/amd64/$BINARY" -o "$BIN_ROOT/$BINARY"
      fi
    done

    # create nodes
    if [ -z "$NODE_NAME" ]; then
      fp "Creating Cluster" "info"
      for NODE in "${NODES[@]}"; do
        deploy_node "$NODE"
      done
    else
      if [[ ! " ${NODES[*]} " =~ ${NODE_NAME} ]]; then
        fp "Hmm i dont know this Node" "danger"
        exit 1
      else
        fp "Create Cluster Node $NODE_NAME" "info"
        NODE="$NODE_NAME"
        deploy_node "$NODE"
      fi
    fi

    fp "Waiting a moment to pull all images" "info"
    sleep 30

    if [ -n "$DEPLOY_CILIUM" ]; then
      fp "Deploy cilium" "info"
      $KUBECTL apply -f "$(pwd)/cilium-rbac.yaml"
      sleep 3
      #SECRET=$($KUBECTL get sa cilium -n kube-system -o json | jq '.secrets[].name' | tr -d '"|\r' | while read -r TOKEN_NAME ; do $KUBECTL -n kube-system get secrets "$TOKEN_NAME" -o json ; done)
      #TOKEN=$(jq -j -r -n --argjson secret "$SECRET" '$secret.data.token' | base64 -d)
      #CA_CERT=$(jq -j -r -n --argjson secret "$SECRET" '$secret.data."ca.crt"')
      #sed -ri 's/^(\s*)(certificate-authority-data:\s.*\s*$)/\1certificate-authority-data: '"$CA_CERT"'/' "$(pwd)/cilium.conf"
      #sed -ri 's/^(\s*)(token:\s.*\s*$)/\1token: '"$TOKEN"'/' "$(pwd)/cilium.conf"
      NODE="master"
      NODE_SSHKEY=$($DOCKER_MACHINE inspect "$NODE" -f '{{.Driver.SSHKeyPath}}')

      convert_path NODE_SSHKEY

      SSH_COMMAND="$SSH_OPTIONS $NODE_SSHKEY"

      rsync -r --rsync-path "sudo rsync" -e "$SSH_COMMAND" "$MASTER_IP_NAT:/var/lib/localkube/certs" "$PKI_ROOT/"
      ETCD_CLIENT_CRT=$(base64 -w0 <"$PKI_ROOT/certs/apiserver-etcd-client.crt")
      ETCD_CLIENT_KEY=$(base64 -w0 <"$PKI_ROOT/certs/apiserver-etcd-client.key")
      ETCD_CA=$(base64 -w0 <"$PKI_ROOT/certs/etcd/ca.crt")
      sed -ri 's/^(\s*)(etcd-ca:\s.*\s*$)/\1etcd-ca: '"$ETCD_CA"'/' "$(pwd)/cilium.yaml"
      sed -ri 's/^(\s*)(etcd-client-key:\s.*\s*$)/\1etcd-client-key: '"$ETCD_CLIENT_KEY"'/' "$(pwd)/cilium.yaml"
      sed -ri 's/^(\s*)(etcd-client-crt:\s.*\s*$)/\1etcd-client-crt: '"$ETCD_CLIENT_CRT"'/' "$(pwd)/cilium.yaml"
      #for NODE in "${NODES[@]}"; do

      #  NODE_IP="${NODE^^}_IP"
      #  NODE_IP="${!NODE_IP}"
      #  NODE_SSHKEY=$($DOCKER_MACHINE inspect "$NODE" -f '{{.Driver.SSHKeyPath}}')

      #  case $OSTYPE in
      #    msys*)
      #      NODE_SSHKEY=$(echo "/$NODE_SSHKEY" | sed 's/\\/\//g' | sed 's/://')
      #      ;;
      #    *) ;;
      #  esac

      #  SSH_COMMAND="$SSH_OPTIONS $NODE_SSHKEY"

      #  $SSH_COMMAND "$NODE_IP" "sudo tee $B2D_DIR/etc/kubernetes/cilium.conf >/dev/null" < "$(pwd)/cilium.conf"
      #done
      $KUBECTL apply -f "$(pwd)/kuberouter.yaml"
      #$KUBECTL apply -f "$(pwd)/cilium.yaml"
    else
      fp "Deploy Flannel" "info"
      $KUBECTL apply -f "$(pwd)/kube-flannel.yaml"
    fi
    ;;
  start)
    if [ -z "$NODE_NAME" ]; then
      fp "Starting Cluster" "info"
      for NODE in "${NODES[@]}"; do
        fp "Starting now Node $NODE" "info"
        $DOCKER_MACHINE start "$NODE" || :
        #$VBOX_MANAGE controlvm "$NODE" nic1 natnetwork "NatNetwork"
      done
    else
      if [[ ! " ${NODES[*]} " =~ ${NODE_NAME} ]]; then
        fp "Hmm i dont know this Node" "danger"
        exit 1
      else
        fp "Start Cluster Node $NODE_NAME" "info"
        $DOCKER_MACHINE start "$NODE_NAME" || :
        #$VBOX_MANAGE controlvm "$NODE_NAME" nic1 natnetwork "NatNetwork"
      fi
    fi
    ;;
  stop)
    if [ -z "$NODE_NAME" ]; then
      fp "Stopping Cluster" "info"
      reverse NODES REV_NODES
      for NODE in "${REV_NODES[@]}"; do
        fp "Stopping now Node $NODE" "info"
        #$VBOX_MANAGE controlvm "$NODE" nic1 nat
        $DOCKER_MACHINE stop "$NODE" || :
      done
    else
      if [[ ! " ${NODES[*]} " =~ ${NODE_NAME} ]]; then
        fp "Hmm i dont know this Node" "danger"
        exit 1
      else
        fp "Stop Cluster Node $NODE_NAME" "info"
        #$VBOX_MANAGE controlvm "$NODE_NAME" nic1 nat
        $DOCKER_MACHINE stop "$NODE_NAME" || :
      fi
    fi
    ;;
  *)
    fp "Usage: $(basename "${BASH_SOURCE[0]}") <command> args..." "info"
    fp "" ""
    fp "Commands:" "warning"
    fp "    create                         Create cluster with given nodes in Variables section of this script" "info"
    fp "" "info"
    fp "    start                          Start already created cluster" "info"
    fp "                                   (in the given order of the Variable NODES)" "info"
    fp "" ""
    fp "    stop                           Stops the cluster" "info"
    fp "                                   (in the reverse order of the Variable NODES)" "info"
    ;;
esac
