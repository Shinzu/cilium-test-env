#! /usr/bin/env bash
# set static ip in vm adopted from https://github.com/fivestars/docker-machine-ipconfig

set -o errexit
set -o pipefail
set -o nounset
#IFS=$'\n\t'

NODES=("master" "worker01")
K8S_VERSION="v1.10.0"
ISO_VERSION="v0.26.0"
MASTER_ROLE="MASTER"
MASTER_MEMORY="8192"
MASTER_CPU="2"
MASTER_DISKSIZE="15000"
MASTER_IP="192.168.99.50"
MASTER_IP_NAT="10.0.2.50"
WORKER01_ROLE="WORKER"
WORKER_MEMORY="2048"
WORKER_CPU="1"
WORKER_DISKSIZE="10000"
WORKER01_IP="192.168.99.51"
WORKER01_IP_NAT="10.0.2.51"
GATEWAY_NAT="10.0.2.1"
BROADCAST="192.168.99.255"
BROADCAST_NAT="10.0.2.255"
SSH_USER="docker"
SSH_OPTIONS="ssh -o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -l docker -i"
SCP_OPTIONS="scp -o LogLevel=error -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i"
HOME_DIR="/C/Users/shinz"
FILE_ROOT="$(pwd)/static_files"
ISO_ROOT="$(pwd)/iso/$ISO_VERSION"
BIN_ROOT="$(pwd)/binaries/$K8S_VERSION"
BINARIES=("kubeadm" "kubelet")
PKI_ROOT="$(pwd)/PKI/docker_ca"
B2D_DIR="/var/lib/boot2docker"
DOCKER_MACHINE="docker-machine"
VBOX_MANAGE="VBoxManage"

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
	for NODE in "${NODES[@]}"; do

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

		$DOCKER_MACHINE create -d "virtualbox" \
			--virtualbox-boot2docker-url "file:/$ISO_ROOT/minikube-$ISO_VERSION.iso" \
			--virtualbox-cpu-count "$CPU" \
			--virtualbox-memory "$MEMORY" \
			--virtualbox-disk-size "$DISKSIZE" \
			--virtualbox-hostonly-nictype "virtio" \
			--virtualbox-nat-nictype "virtio" \
			"$NODE" || :

		NODE_SSHKEY=$($DOCKER_MACHINE inspect "$NODE" -f '{{.Driver.SSHKeyPath}}')

		case $OSTYPE in
		msys*)
			NODE_SSHKEY=$(echo "/$NODE_SSHKEY" | sed 's/\\/\//g' | sed 's/://')
			;;
		*) ;;

		esac

		DHCP_IP=$($DOCKER_MACHINE ip "$NODE")
		SSH_COMMAND="$SSH_OPTIONS $NODE_SSHKEY"
		SCP_COMMAND="$SCP_OPTIONS $NODE_SSHKEY"

		# set natnetwork on internal network if
		$VBOX_MANAGE controlvm "$NODE" nic1 natnetwork "NatNetwork"
		# set portwarding
		# $VBOX_MANAGE natnetwork modify --netname "NatNetwork" --port-forward-4 "master:tcp:[]:10050:[${NODE_IP_NAT}]:22"

		while true; do
			MOUNT_RDY=$($SSH_COMMAND "$DHCP_IP" "mount -l | grep boot2docker" || :)
			if [[ ! -z $MOUNT_RDY ]]; then
				break
			fi
			sleep 5
		done

		# create directory structure
		$SSH_COMMAND "$DHCP_IP" "sudo mkdir -p $B2D_DIR/etc/systemd/system && \
                sudo chown docker:docker $B2D_DIR/etc/systemd/system && \
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
		$SCP_COMMAND "$PKI_ROOT/certs/$NODE.crt" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/server.pem"
		$SCP_COMMAND "$PKI_ROOT/certs/docker_ca.crt" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/ca.pem"
		$SCP_COMMAND "$PKI_ROOT/keys/$NODE.key" "$SSH_USER@$DHCP_IP:$B2D_DIR/etc/docker/server-key.pem"
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
    --allow-privileged=true\
    --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
    --pod-manifest-path=/etc/kubernetes/manifests \
    --cluster-dns=10.96.0.10 \
    --cluster-domain=cluster.local \
    --authorization-mode=Webhook \
    --cadvisor-port=0 \
    --fail-swap-on=false \
    --kubeconfig=/etc/kubernetes/kubelet.conf \
    --network-plugin=cni \
    --feature-gates=CustomResourceValidation=true

[Install]
Wants=docker.socket
EOF
		else
			cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee $B2D_DIR/etc/systemd/system/kubelet.service.d/10-kubeadm.conf >/dev/null"
[Service]
ExecStart=
ExecStart=/usr/bin/kubelet --cgroup-driver=cgroupfs \
    --hostname-override=$NODE \
    --allow-privileged=true\
    --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
    --pod-manifest-path=/etc/kubernetes/manifests \
    --cluster-dns=10.96.0.10 \
    --cluster-domain=cluster.local \
    --authorization-mode=Webhook \
    --cadvisor-port=0 \
    --fail-swap-on=false \
    --kubeconfig=/etc/kubernetes/kubelet.conf \
    --network-plugin=cni \
    --feature-gates=CustomResourceValidation=true

[Install]
Wants=docker.socket
EOF
		fi

		cat <<EOF | $SSH_COMMAND "$DHCP_IP" "sudo tee -a $B2D_DIR/bootlocal.sh >/dev/null && sudo chmod u+x $B2D_DIR/bootlocal.sh && sudo $B2D_DIR/bootlocal.sh" || :
#!/bin/sh

# Stop the DHCP service for our host-only inteface
[[ -f /var/run/udhcpc.eth1.pid ]] && kill \$(cat /var/run/udhcpc.eth1.pid) 2>/dev/null || :

# Configure the interface to use the assigned IP address as a static address
ifconfig eth1 $NODE_IP netmask 255.255.255.0 broadcast $BROADCAST up

# kill dhcp on eth0
[[ -f /var/run/udhcpc.eth0.pid ]] && kill \$(cat /var/run/udhcpc.eth0.pid) 2>/dev/null || :

# wait until natnetwork is up
while true; do
    GW=\$(ip r | grep default | awk '{print \$3}')
    if [ \$GW = "10.0.2.1" ]; then
        break
    fi
    sleep 1
done

# set ip eth0
ifconfig eth0 $NODE_IP_NAT netmask 255.255.255.0 broadcast $BROADCAST_NAT up

# clean/add routes
ip route add default via $GATEWAY_NAT

# set hostname
/bin/hostname $NODE
sed -i 's/minikube/$NODE/g' /etc/hosts

# disable swap
swapoff -a

# link services/binaries
ln -s $B2D_DIR/etc/docker/server.pem /etc/docker/server.pem
ln -s $B2D_DIR/etc/docker/server-key.pem /etc/docker/server-key.pem
ln -s $B2D_DIR/etc/docker/ca.pem /etc/docker/ca.pem
ln -s $B2D_DIR/etc/sysconfig/crio.minikube /etc/sysconfig/crio.minikube
ln -s $B2D_DIR/etc/systemd/system/kubelet.service.d /etc/systemd/system/kubelet.service.d
ln -s $B2D_DIR/etc/systemd/system/kubelet.service /etc/systemd/system/kubelet.service
ln -s $B2D_DIR/etc/systemd/system/docker.service /etc/systemd/system/docker.service
chmod +x $B2D_DIR/usr/bin/kubelet
chmod +x $B2D_DIR/usr/bin/kubeadm
ln -s $B2D_DIR/usr/bin/kubelet /usr/bin/kubelet
ln -s $B2D_DIR/usr/bin/kubeadm /usr/bin/kubeadm
sed -i 's/mkdir/\/bin\/mkdir/g' /lib/systemd/system/crio-shutdown.service
mkdir -p /mnt/sda1/var/lib/crio
mkdir -p /var/lib/crio
mount --bind /mnt/sda1/var/lib/crio /var/lib/crio

# mount bpffs
mount bpffs /sys/fs/bpf -t bpf

# sync kubernetes directory if node was already provisioned
if [ -f $B2D_DIR/etc/kubernetes/admin.conf ]; then
    ln -s $B2D_DIR/etc/kubernetes /etc/kubernetes
fi

# reload/start services
systemctl daemon-reload
systemctl enable docker.service
systemctl enable kubelet.service
(sleep 10; systemctl restart crio.service ; systemctl start docker.service ; systemctl start kubelet.service) &
EOF

		# write kubeadm conf on master
		if [ "$NODE_ROLE" == "MASTER" ]; then
			while true; do
				fp "Trying connection to new static ip" "info"
				if $SSH_COMMAND "$NODE_IP" "exit"; then
					break
				fi
				sleep 1
			done
			cat <<EOF | $SSH_COMMAND "$NODE_IP" "sudo tee -a /var/lib/kubeadm.yaml >/dev/null"
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
  authorization-mode: "RBAC"
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
			$SSH_COMMAND "$NODE_IP" "sudo /usr/bin/kubeadm init --config /var/lib/kubeadm.yaml \
                    --ignore-preflight-errors=DirAvailable--etc-kubernetes-manifests \
                    --ignore-preflight-errors=DirAvailable--data \
                    --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-scheduler.yaml \
                    --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-apiserver.yaml \
                    --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-kube-controller-manager.yaml \
                    --ignore-preflight-errors=FileAvailable--etc-kubernetes-manifests-etcd.yaml \
                    --ignore-preflight-errors=Swap \
                    --ignore-preflight-errors=CRI"

			$SSH_COMMAND "$NODE_IP" "sudo cat /etc/kubernetes/admin.conf" >$HOME_DIR/.kube/config
			$SSH_COMMAND "$NODE_IP" "sudo rsync -av -q /etc/kubernetes/ $B2D_DIR/etc/kubernetes/"
		else
			fp "You must join this Worker Node with the command provided with the Outout of kubeadm from the master node" "warning"
		fi
	done
	;;
start)
	if [ "$NODE_NAME" == "" ]; then
		fp "Starting Cluster" "info"
		for NODE in "${NODES[@]}"; do
			fp "Starting now Node $NODE" "info"
			$DOCKER_MACHINE start "$NODE" || :
			$VBOX_MANAGE controlvm "$NODE" nic1 natnetwork "NatNetwork"
		done
	else
		if [[ ! " ${NODES[*]} " =~ ${NODE_NAME} ]]; then
			fp "Hmm i dont know this Node" "danger"
			exit 1
		else
			fp "Start Cluster Node $NODE_NAME" "info"
			$DOCKER_MACHINE start "$NODE_NAME" || :
			$VBOX_MANAGE controlvm "$NODE_NAME" nic1 natnetwork "NatNetwork"
		fi
	fi
	;;
stop)
	if [ "$NODE_NAME" == "" ]; then
		fp "Stopping Cluster" "info"
		reverse NODES REV_NODES
		for NODE in "${REV_NODES[@]}"; do
			fp "Stopping now Node $NODE" "info"
			$VBOX_MANAGE controlvm "$NODE" nic1 nat
			$DOCKER_MACHINE stop "$NODE" || :
		done
	else
		if [[ ! " ${NODES[*]} " =~ ${NODE_NAME} ]]; then
			fp "Hmm i dont know this Node" "danger"
			exit 1
		else
			fp "Stop Cluster Node $NODE_NAME" "info"
			$VBOX_MANAGE controlvm "$NODE_NAME" nic1 nat
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
