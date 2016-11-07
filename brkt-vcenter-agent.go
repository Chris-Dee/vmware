package main

import (
	"fmt"
	"net/url"
	"os"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"context"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/object"
	"encoding/json"
	"net/http"
	"bytes"
	"net"
	"time"
	"crypto/tls"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"strings"
	"github.com/urfave/cli"
	"sort"
)

// Command line arguments.
var serviceURLString string
var vCenterURLString string
var maxConsecutiveFailures int
var sleepDuration time.Duration
var noVcenterVerifyCert bool
var noServiceVerifyCert bool
var token string
var tokenPath string
var verbose bool

// Initialized from command line arguments.
var serviceURL url.URL
var vCenterURL url.URL

func exit(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}

func getDatacenterProperties(ctx context.Context, client *vim25.Client,
		finderDatacenters []*object.Datacenter) ([]mo.Datacenter, error) {
	pc := property.DefaultCollector(client)
	var refs []types.ManagedObjectReference
	for _, finderDC := range finderDatacenters {
		refs = append(refs, finderDC.Reference())
	}
	var datacenters []mo.Datacenter
	err := pc.Retrieve(ctx, refs, []string{"name"}, &datacenters)
	if err != nil {
		return datacenters, fmt.Errorf("Unable to retrieve Datacenters: %s", err)
	}
	return datacenters, nil
}

// dedupe removes duplicates from a slice of ManageObjectReferences
func dedupe(refs []types.ManagedObjectReference) []types.ManagedObjectReference {
	m := make(map[string]bool)
	deduped := make([]types.ManagedObjectReference, 0)
	for _, ref := range refs {
		if _, ok := m[ref.Value]; !ok {
			deduped = append(deduped, ref)
			m[ref.Value] = true
		}
	}
	return deduped
}

func getVMProperties(ctx context.Context, client *vim25.Client,
		refs []types.ManagedObjectReference) ([]mo.VirtualMachine, error) {
	pc := property.DefaultCollector(client)
	var vms []mo.VirtualMachine
	err := pc.Retrieve(ctx, dedupe(refs), []string{"name", "config", "guest", "resourcePool"}, &vms)
	if err != nil {
		return vms, fmt.Errorf("Unable to retrieve VMs: %s", err)
	}

	return vms, nil
}

func getResourcePoolProperties(ctx context.Context, client *vim25.Client,
		refs []types.ManagedObjectReference) ([]mo.ResourcePool, error) {
	pc := property.DefaultCollector(client)
	var resourcePools []mo.ResourcePool
	err := pc.Retrieve(ctx, dedupe(refs), []string{"owner", "vm"}, &resourcePools)
	if err != nil {
		return resourcePools, fmt.Errorf("Unable to retrieve ResourcePools: %s", err)
	}

	return resourcePools, nil
}

func getComputeResourceProperties(ctx context.Context, client *vim25.Client,
		refs []types.ManagedObjectReference) ([]mo.ComputeResource, error) {
	pc := property.DefaultCollector(client)
	var computeResources []mo.ComputeResource
	err := pc.Retrieve(ctx, dedupe(refs), []string{"name"}, &computeResources)
	if err != nil {
		return computeResources, fmt.Errorf("Unable to retrieve ComputeResources: %s", err)
	}

	return computeResources, nil
}

type virtualMachine struct {
	DatacenterName string `json:"datacenter_name"`
	ClusterName    string `json:"cluster_name"`
	GuestId        string `json:"guest_id,omitempty"`
	InstanceUuid   string `json:"instance_uuid,omitempty"`
	MacAddress     string `json:"mac_address"`
	Name           string `json:"name"`
	Uuid           string `json:"uuid"`
}

type putVirtualMachines struct {
	VirtualMachines []virtualMachine `json:"virtual_machines"`
}

// getVirtualMachines loads virtual machine properties from vCenter.
func getVirtualMachines(ctx context.Context) ([]virtualMachine, error) {
	log.Infof("Getting virtual machines from vCenter at %s", vCenterURL.Host)
	returnedVMs := make([]virtualMachine, 0)

	// Connect and log in to ESX or vCenter
	c, err := govmomi.NewClient(ctx, &vCenterURL, noVcenterVerifyCert)
	if err != nil {
		return returnedVMs, err
	}

	f := find.NewFinder(c.Client, true)

	// Get datacenter properties.
	finderDatacenters, err := f.DatacenterList(ctx, "*")
	if err != nil {
		return returnedVMs, fmt.Errorf("Unable to get Datacenters: %s", err)
	}
	log.Debugf("Found %d Datacenters", len(finderDatacenters))
	datacenters, err := getDatacenterProperties(ctx, c.Client, finderDatacenters)
	if err != nil {
		return returnedVMs, fmt.Errorf("Unable to get Datacenter properties: %s", err)
	}

	// Get virtual machines and their properties for each datacenter.
	for i, fdc := range finderDatacenters {
		path := fmt.Sprintf("%s/vm/*", fdc.InventoryPath)
		log.Debugf("Getting Virtual Machine list from %s", path)
		finderVMs, err := f.VirtualMachineList(ctx, path)
		if err != nil {
			return returnedVMs, fmt.Errorf("Unable to get VM list: %s", err)
		}
		log.Debugf("Found %d VMs in Datacenter %s", len(finderVMs), fdc.Name())

		// Get VM properties.
		refs := make([]types.ManagedObjectReference, 0)
		for _, finderVM := range finderVMs {
			refs = append(refs, finderVM.Reference())
		}
		vms, err := getVMProperties(ctx, c.Client, refs)
		if err != nil {
			return returnedVMs, err
		}

		// Get ResourcePool properties for all VMs.
		refs = make([]types.ManagedObjectReference, 0)
		for _, vm := range vms {
			if vm.ResourcePool != nil {
				refs = append(refs, vm.ResourcePool.Reference())
			}
		}

		rpps, err := getResourcePoolProperties(ctx, c.Client, refs)
		if err != nil {
			return returnedVMs, err
		}
		resourcePools := make(map[string]mo.ResourcePool)
		for _, rpp := range rpps {
			resourcePools[rpp.Reference().Value] = rpp
		}

		// Get ResourcePool owners.
		refs = make([]types.ManagedObjectReference, 0)
		for _, rp := range resourcePools {
			refs = append(refs, rp.Owner)
		}

		crps, err := getComputeResourceProperties(ctx, c.Client, refs)
		if err != nil {
			return returnedVMs, err
		}
		computeResources := make(map[string]mo.ComputeResource)
		for _, crp := range crps {
			computeResources[crp.Reference().Value] = crp
		}

		// Create virtualMachine objects based on the values we
		// just read from vCenter.
		for _, vm := range vms {
			rvm := virtualMachine{
				DatacenterName: datacenters[i].Name,
				Name: vm.Name,
			}
			if vm.Config != nil {
				rvm.GuestId = vm.Config.GuestId
				rvm.InstanceUuid = vm.Config.InstanceUuid
				rvm.Uuid = vm.Config.Uuid
			}
			if len(vm.Guest.Net) > 0 {
				rvm.MacAddress = vm.Guest.Net[0].MacAddress
			}
			if vm.ResourcePool != nil {
				rp := resourcePools[vm.ResourcePool.Value]
				rvm.ClusterName = computeResources[rp.Owner.Value].Name
			}
			returnedVMs = append(returnedVMs, rvm)
		}

	}

	return returnedVMs, nil
}

func replaceVMProperties(vms []virtualMachine) error {
	log.Infof("Sending properties for %d VMs to the Bracket service at %s", len(vms), serviceURL.Host)
	// Initialize HTTP client.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
	}

	if serviceURL.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: noServiceVerifyCert}
		transport.TLSHandshakeTimeout = 10 * time.Second
	}
	client := http.Client{Transport: transport}

	payload := putVirtualMachines{VirtualMachines: vms}
	b, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/api/v1/vmwprops/virtual_machine", serviceURL.String())
	req, err := http.NewRequest("PUT", url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("Cannot create a request to the Bracket service: %s", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error while sending request to the Bracket service: %s", err)
	}
	if resp.StatusCode / 100 != 2 {
		if log.GetLevel() >= log.DebugLevel {
			// Log the payload in verbose mode.
			b, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if len(b) > 0 {
				log.Debugf(string(b))
			}
		}

		msg := fmt.Sprintf("Bracket service returned %s", resp.Status)
		if resp.StatusCode / 100 == 4 {
			return dontRetryError{msg: msg}
		}
		return fmt.Errorf("Bracket service returned %s", resp.Status)

	}
	return nil
}

// dontRetryError tells the error handling code to exit immediately because
// this error is permanent.
type dontRetryError struct {
	msg string
}

func (e dontRetryError) Error() string {
	return e.msg
}

func doIt() error {
	ctx, cancel := context.WithCancel(context.Background())
	// Clean up govmomi resources when this function exits.
	defer cancel()

	// Get VM properties from vCenter.
	vms, err := getVirtualMachines(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect user name or password") {
			msg := fmt.Sprintf("Authentication with vCenter failed: %s", err.Error())
			return dontRetryError{msg: msg}
		}
		return err
	}

	// Filter out VMs that don't have a network interface.
	vmsWithNIC := make([]virtualMachine, 0)
	for _, vm := range vms {
		if len(vm.MacAddress) > 0 {
			vmsWithNIC = append(vmsWithNIC, vm)
		}
	}

	// Send VM properties to the Bracket service.
	if len(vmsWithNIC) > 0 {
		err = replaceVMProperties(vmsWithNIC)
		if err != nil {
			return err
		}
	}

	return nil
}

func handleArgs() error {
	// Check required arguments.
	if len(vCenterURLString) == 0 {
		return fmt.Errorf("--vcenter-url or $BRKT_VCENTER_URL is required")
	}
	if len(token) == 0 {
		if len(tokenPath) == 0 {
			return fmt.Errorf("--token or --token-path is required")
		}

		// Read token.
		b, err := ioutil.ReadFile(tokenPath)
		if err != nil {
			return fmt.Errorf("Unable to read %s: %s", tokenPath, err)
		}
		token = strings.TrimSpace(string(b))
	}

	// Parse URLs.
	u, err := url.Parse(vCenterURLString)
	if err != nil {
		return fmt.Errorf("Unable to parse vCenter URL: %s", err)
	}
	vCenterURL = *u

	u, err = url.Parse(serviceURLString)
	if err != nil {
		return fmt.Errorf("Unable to parse Bracket service URL: %s", err)
	}
	serviceURL = *u

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	return nil
}

func run(c *cli.Context) {
	err := handleArgs()
	if err != nil {
		exit(err)
	}

	// Keep track of the number of consecutive failures.  The vCenter
	// API connection fails pretty frequently due to TLS handshake errors.
	// This also prevents the agent from exiting if there's a temporary
	// network outage.
	consecutiveFailures := 0

	for true {
		err := doIt()
		if err != nil {
			if _, ok := err.(dontRetryError); ok {
				// Don't retry on auth error.
				exit(err)
			}

			log.Info(err)
			consecutiveFailures += 1
		} else {
			consecutiveFailures = 0
		}
		if consecutiveFailures > maxConsecutiveFailures {
			break
		}
		log.Infof("Sleeping for %s", sleepDuration)
		time.Sleep(sleepDuration)
	}

	exit(fmt.Errorf("Exiting after %d failures", consecutiveFailures))
}

func main() {
	app := cli.NewApp()
	app.Usage = "synchronize instance properties between vCenter and the Bracket service."
	app.Version = "0.9.0"
	app.Action = run
	app.Flags = []cli.Flag {
		cli.StringFlag{
			Name: "service-url",
			Value: "https://mgmt.brkt.com",
			Usage: "Bracket service `URL`",
			Destination: &serviceURLString,
		},
		cli.StringFlag{
			Name: "vcenter-url",
			Usage: "vCenter API `URL` (required, example: https://username:password@host/sdk)",
			Destination: &vCenterURLString,
			EnvVar: "BRKT_VCENTER_URL",
		},
		cli.IntFlag{
			Name: "max-consecutive-failures",
			Value: 5,
			Usage: "Exit after `N` consecutive failures",
			Destination: &maxConsecutiveFailures,
		},
		cli.DurationFlag{
			Name: "sleep-duration",
			Value: time.Minute,
			Usage: "Sleep `DURATION` between connections to vCenter",
			Destination: &sleepDuration,
		},
		cli.BoolFlag{
			Name: "no-service-verify-cert",
			Usage: "Don't verify the SSL certificate of the Bracket service",
			Destination: &noServiceVerifyCert,
		},
		cli.BoolFlag{
			Name: "no-vcenter-verify-cert",
			Usage: "Don't verify the SSL certificate of the vCenter server",
			Destination: &noVcenterVerifyCert,
		},
		cli.StringFlag{
			Name: "token",
			Usage: "Bracket service auth token",
			EnvVar: "BRKT_TOKEN",
			Destination: &token,
		},
		cli.StringFlag{
			Name: "token-path",
			Usage: "Read Bracket service auth token from `PATH`",
			Destination: &tokenPath,
		},
		cli.BoolFlag{
			Name: "verbose",
			Usage: "Enable verbose logging",
			Destination: &verbose,
		},
	}
	sort.Sort(cli.FlagsByName(app.Flags))
	err := app.Run(os.Args)
	if err != nil {
		exit(err)
	}

}
