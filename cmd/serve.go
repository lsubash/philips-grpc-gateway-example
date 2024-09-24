package cmd

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
    //"bytes"
	"github.com/philips/grpc-gateway-example/pkg/ui/data/swagger"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/philips/go-bindata-assetfs"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	pb "github.com/philips/grpc-gateway-example/echopb"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the example webserver on https://localhost:10000",
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

func init() {
	RootCmd.AddCommand(serveCmd)
}

type myService struct{
	pb.UnimplementedEchoServiceServer
}

func (m *myService) Cmsversion(c context.Context, s *pb.EchoMessage) (*wrapperspb.StringValue, error) {
//func (m *myService) Cmsversion(c context.Context, s *pb.EchoMessage) (*pb.EchoReply, error) {
	fmt.Printf("Enter Cmsversion\n")
	url := "https://10.34.40.201:30445/cms/v1/version"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
        if err != nil {
                fmt.Printf("GET Failed")
		log.Fatal(err)
        }

        client := &http.Client{Transport: tr}
        resp, err := client.Do(req)
        if err != nil {
        	fmt.Printf("GET Failed 2")
		log.Fatal(err)
        }

        defer resp.Body.Close()


	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)

	//return bodyText, nil
	str := string(bodyText)
	return wrapperspb.String(str), nil
}

func (m *myService) Cmscacert(c context.Context, s *pb.EchoMessage) (*pb.EchoReply, error) {
	fmt.Printf("Enter Cmscacert\n")
	url := "https://10.34.40.201:30445/cms/v1/ca-certificates"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
			fmt.Printf("GET Failed")
	log.Fatal(err)
	}

	client := &http.Client{Transport: tr}
	req.Header.Set("Accept", "application/x-pem-file")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("GET Failed 2")
	log.Fatal(err)
	}

	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)

	//return bodyText, nil
	return &pb.EchoReply{
		Value: fmt.Sprintf("\n%s\n", bodyText),
	}, nil
}

func (m *myService) Aasversion(c context.Context, s *pb.EchoMessage) (*pb.EchoReply, error) {
	fmt.Printf("Enter Aasversion\n") 
	url := "https://10.34.40.201:30444/aas/v1/version"
        //data := []byte(s.Value)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
        if err != nil {
                fmt.Printf("GET Failed")
		log.Fatal(err)
        }

        client := &http.Client{Transport: tr}
        resp, err := client.Do(req)
        if err != nil {
        	fmt.Printf("GET Failed 2")
		log.Fatal(err)
        }

        defer resp.Body.Close()


	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)

	//return bodyText, nil
	return &pb.EchoReply{
		Value: fmt.Sprintf("\n%s\n", bodyText),
	}, nil
}


func (m *myService) Hvsversion(c context.Context, s *pb.EchoMessage) (*pb.EchoReply, error) {
	fmt.Printf("Enter Hvsversion\n")
	url := "https://10.34.40.201:30443/hvs/v2/version"

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
        if err != nil {
                fmt.Printf("GET Failed")
		log.Fatal(err)
        }

        client := &http.Client{Transport: tr}
        resp, err := client.Do(req)
        if err != nil {
        	fmt.Printf("GET Failed 2")
		log.Fatal(err)
        }

        defer resp.Body.Close()


	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)

	//return bodyText, nil
	return &pb.EchoReply{
		Value: fmt.Sprintf("\n%s\n", bodyText),
	}, nil
}

func (m *myService) Aasgettoken(c context.Context, s *pb.Aastoken) (*pb.EchoReply, error) {
	fmt.Printf("Enter Aasgettoken\n")

	url := "https://10.34.40.201:30444/aas/v1/token"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	var data2 = strings.NewReader(fmt.Sprintf("{\n  \"username\" : \"%s\", \"password\" : \"%s\" \n}", s.Username,s.Password))

	req, err := http.NewRequest(http.MethodPost, url, data2)
	if err != nil {
		fmt.Printf("GET Failed")
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("GET Failed 2")
		log.Fatal(err)
	}

	defer resp.Body.Close()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)

	//return bodyText, nil
	return &pb.EchoReply{
		Value: fmt.Sprintf("\n%s\n", bodyText),
	}, nil
}

func newServer() *myService {
	return new(myService)
}

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO(tamird): point to merged gRPC code rather than a PR.
		// This is a partial recreation of gRPC's internal checks https://github.com/grpc/grpc-go/pull/514/files#diff-95e9a25b738459a2d3030e1e6fa2a718R61
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func serveSwagger(mux *http.ServeMux) {
	mime.AddExtensionType(".svg", "image/svg+xml")

	// Expose files in third_party/swagger-ui/ on <host>/swagger-ui
	fileServer := http.FileServer(&assetfs.AssetFS{
		Asset:    swagger.Asset,
		AssetDir: swagger.AssetDir,
		Prefix:   "third_party/swagger-ui",
	})
	prefix := "/swagger-ui/"
	mux.Handle(prefix, http.StripPrefix(prefix, fileServer))
}

func serve() {
	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewClientTLSFromCert(demoCertPool, "localhost:10000"))}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterEchoServiceServer(grpcServer, newServer())
	ctx := context.Background()

	dcreds := credentials.NewTLS(&tls.Config{
		ServerName: demoAddr,
		RootCAs:    demoCertPool,
		InsecureSkipVerify: true,
	})
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(dcreds)}

	mux := http.NewServeMux()
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, strings.NewReader(pb.Swagger))
	})

	gwmux := runtime.NewServeMux()
	err := pb.RegisterEchoServiceHandlerFromEndpoint(ctx, gwmux, demoAddr, dopts)
	if err != nil {
		fmt.Printf("serve: %v\n", err)
		return
	}

	mux.Handle("/", gwmux)
	serveSwagger(mux)

	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:    demoAddr,
		Handler: grpcHandlerFunc(grpcServer, mux),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*demoKeyPair},
			NextProtos:   []string{"h2"},
		},
	}

	fmt.Printf("grpc on port: %d\n", port)
	err = srv.Serve(tls.NewListener(conn, srv.TLSConfig))

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

	return
}
