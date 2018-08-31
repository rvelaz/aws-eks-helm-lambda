package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubernetes-sigs/aws-iam-authenticator/pkg/token"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/pkg/errors"
	// "errors"

	log "github.com/sirupsen/logrus"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/helm/pkg/helm"
	helm_env "k8s.io/helm/pkg/helm/environment"
	"k8s.io/helm/pkg/helm/portforwarder"
	rls "k8s.io/helm/pkg/proto/hapi/services"
)

func main() {
	if os.Getenv("ENV") != "PRODUCTION" {
		log.SetLevel(log.DebugLevel)
	}

	lambda.Start(handler)
}

func handler(context context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Start a new AWS session
	s := newSession()

	// Setup the basic EKS cluster info
	cfg := &ClusterConfig{
		ClusterName: os.Getenv("CLUSTER_NAME"),
		Session:     s,
	}

	// Load the rest from AWS using SDK
	cfg.loadConfig()

	// Create the Kubernetes client
	client, err := cfg.NewClientConfig()
	if err != nil {
		log.WithError(err).Fatal(err.Error())
	}

	clientset, err, clientConfig := client.NewClientSetWithEmbeddedToken()
	if err != nil {
		log.WithError(err).Fatal(err.Error())
	}

	// Call Kubernetes API here
	pods, err := clientset.CoreV1().Pods("").List(metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Fatal("Error listing pods")
	}

	var results []string

	for i, pod := range pods.Items {
		log.Infof("[%d] %s", i, pod.Name)
		results = append(results, pod.Name)
	}

	log.Info("About to get Helm release list")
	lr, _ := ListDeployments(clientset, clientConfig)
	for _, release := range lr.Releases {
		log.Infof("Release: %s", release.Name)
	}

	json, err := json.Marshal(results)
	if err != nil {
		log.WithError(err).Fatal("Unable to marshal results to json")

	}

	return events.APIGatewayProxyResponse{Body: string(json), StatusCode: 200}, nil
}

// Retrieve EKS cluster endpoint and CA from AWS
func (c *ClusterConfig) loadConfig() {
	svc := eks.New(c.Session)
	input := &eks.DescribeClusterInput{
		Name: aws.String(c.ClusterName),
	}

	log.WithField("cluster", c.ClusterName).Info("Looking up EKS cluster")

	result, err := svc.DescribeCluster(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			errors.Wrap(err, aerr.Error())
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			errors.Wrap(err, err.Error())
		}
	}

	log.WithField("cluster", c.ClusterName).Info("Found cluster")
	log.WithField("cluster", result.Cluster).Debug("Cluster details")

	c.MasterEndpoint = *result.Cluster.Endpoint
	c.CertificateAuthorityData = *result.Cluster.CertificateAuthority.Data
}

func (c *ClusterConfig) NewClientConfig() (*ClientConfig, error) {

	stsAPI := sts.New(c.Session)

	iamRoleARN, err := checkAuth(stsAPI)
	if err != nil {
		return nil, err
	}
	contextName := fmt.Sprintf("%s@%s", getUsername(iamRoleARN), c.ClusterName)

	data, err := base64.StdEncoding.DecodeString(c.CertificateAuthorityData)
	if err != nil {
		return nil, errors.Wrap(err, "decoding certificate authority data")
	}

	log.Info("Creating Kubernetes client config")
	clientConfig := &ClientConfig{
		Client: &clientcmdapi.Config{
			Clusters: map[string]*clientcmdapi.Cluster{
				c.ClusterName: {
					Server: c.MasterEndpoint,
					CertificateAuthorityData: data,
				},
			},
			Contexts: map[string]*clientcmdapi.Context{
				contextName: {
					Cluster:  c.ClusterName,
					AuthInfo: contextName,
				},
			},
			AuthInfos: map[string]*clientcmdapi.AuthInfo{
				contextName: &clientcmdapi.AuthInfo{},
			},
			CurrentContext: contextName,
		},
		ClusterName: c.ClusterName,
		ContextName: contextName,
		roleARN:     iamRoleARN,
		sts:         stsAPI,
	}

	return clientConfig, nil

}

func newSession() *session.Session {
	config := aws.NewConfig()
	config = config.WithCredentialsChainVerboseErrors(true)

	opts := session.Options{
		Config:                  *config,
		SharedConfigState:       session.SharedConfigEnable,
		AssumeRoleTokenProvider: stscreds.StdinTokenProvider,
	}

	stscreds.DefaultDuration = 30 * time.Minute

	return session.Must(session.NewSessionWithOptions(opts))
}

func checkAuth(stsAPI stsiface.STSAPI) (string, error) {
	input := &sts.GetCallerIdentityInput{}
	output, err := stsAPI.GetCallerIdentity(input)
	if err != nil {
		return "", errors.Wrap(err, "checking AWS STS access – cannot get role ARN for current session")
	}
	iamRoleARN := *output.Arn
	log.Debugf("role ARN for the current session is %s", iamRoleARN)
	return iamRoleARN, nil
}

type ClusterConfig struct {
	ClusterName              string
	MasterEndpoint           string
	CertificateAuthorityData string
	Session                  *session.Session
}

type ClientConfig struct {
	Client      *clientcmdapi.Config
	ClusterName string
	ContextName string
	roleARN     string
	sts         stsiface.STSAPI
}

func getUsername(iamRoleARN string) string {
	usernameParts := strings.Split(iamRoleARN, "/")
	if len(usernameParts) > 1 {
		return usernameParts[len(usernameParts)-1]
	}
	return "iam-root-account"
}

func (c *ClientConfig) WithEmbeddedToken() (*ClientConfig, error) {
	clientConfigCopy := *c

	log.Info("Generating token")

	gen, err := token.NewGenerator()
	if err != nil {
		return nil, errors.Wrap(err, "could not get token generator")
	}

	tok, err := gen.GetWithSTS(c.ClusterName, c.sts.(*sts.STS))
	if err != nil {
		return nil, errors.Wrap(err, "could not get token")
	}

	x := c.Client.AuthInfos[c.ContextName]
	x.Token = tok

	log.WithField("token", tok).Debug("Successfully generated token")
	return &clientConfigCopy, nil
}

func (c *ClientConfig) NewClientSetWithEmbeddedToken() (*clientset.Clientset, error, *rest.Config) {
	clientConfig, err := c.WithEmbeddedToken()
	if err != nil {
		return nil, errors.Wrap(err, "creating Kubernetes client config with embedded token"), nil
	}
	clientSet, err, config := clientConfig.NewClientSet()
	if err != nil {
		return nil, errors.Wrap(err, "creating Kubernetes client"), nil
	}
	return clientSet, nil, config
}

func (c *ClientConfig) NewClientSet() (*clientset.Clientset, error, *rest.Config) {
	clientConfig, err := clientcmd.NewDefaultClientConfig(*c.Client, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create API client configuration from client config"), clientConfig
	}

	client, err := clientset.NewForConfig(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create API client"), clientConfig
	}
	return client, nil, clientConfig
}

var (
	settings helm_env.EnvSettings
)

// https://github.com/banzaicloud/pipeline/tree/master/helm
func ListDeployments(client *clientset.Clientset, clientConfig *rest.Config) (*rls.ListReleasesResponse, error) {
	hClient, err := GetHelmClient(client, clientConfig)
	// TODO doc the options here
	var sortBy = int32(2)
	var sortOrd = int32(1)
	ops := []helm.ReleaseListOption{
		helm.ReleaseListSort(sortBy),
		helm.ReleaseListOrder(sortOrd),
	}
	if err != nil {
		return nil, err
	}
	resp, err := hClient.ListReleases(ops...)
	if err != nil {
		return nil, err
	}
	// resp.
	return resp, nil
}

func GetHelmClient(client *clientset.Clientset, clientConfig *rest.Config) (*helm.Client, error) {
	tillerTunnel, err := portforwarder.New("kube-system", client, clientConfig)
	if err != nil {
		return nil, err
	}
	tillerTunnelAddress := fmt.Sprintf("localhost:%d", tillerTunnel.Local)
	hclient := helm.NewClient(helm.Host(tillerTunnelAddress))
	return hclient, nil
}
