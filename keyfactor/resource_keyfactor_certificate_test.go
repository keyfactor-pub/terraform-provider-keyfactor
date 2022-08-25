package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"reflect"
	"testing"
)

func Test_downloadCertificate(t *testing.T) {
	type args struct {
		id            int
		kfClient      *api.Client
		password      string
		csrEnrollment bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		want2   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2, err := downloadCertificate(tt.args.id, tt.args.kfClient, tt.args.password, tt.args.csrEnrollment)
			if (err != nil) != tt.wantErr {
				t.Errorf("downloadCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("downloadCertificate() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("downloadCertificate() got1 = %v, want %v", got1, tt.want1)
			}
			if got2 != tt.want2 {
				t.Errorf("downloadCertificate() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func Test_resourceKeyfactorCertificateType_GetSchema(t *testing.T) {
	type args struct {
		in0 context.Context
	}
	tests := []struct {
		name  string
		args  args
		want  tfsdk.Schema
		want1 diag.Diagnostics
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificateType{}
			got, got1 := r.GetSchema(tt.args.in0)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSchema() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GetSchema() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_resourceKeyfactorCertificateType_NewResource(t *testing.T) {
	type args struct {
		in0 context.Context
		p   tfsdk.Provider
	}
	tests := []struct {
		name  string
		args  args
		want  tfsdk.Resource
		want1 diag.Diagnostics
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificateType{}
			got, got1 := r.NewResource(tt.args.in0, tt.args.p)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResource() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("NewResource() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_resourceKeyfactorCertificate_Create(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.CreateResourceRequest
		response *tfsdk.CreateResourceResponse
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificate{
				p: tt.fields.p,
			}
			r.Create(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}

func Test_resourceKeyfactorCertificate_Delete(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.DeleteResourceRequest
		response *tfsdk.DeleteResourceResponse
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificate{
				p: tt.fields.p,
			}
			r.Delete(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}

func Test_resourceKeyfactorCertificate_ImportState(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.ImportResourceStateRequest
		response *tfsdk.ImportResourceStateResponse
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificate{
				p: tt.fields.p,
			}
			r.ImportState(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}

func Test_resourceKeyfactorCertificate_Read(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.ReadResourceRequest
		response *tfsdk.ReadResourceResponse
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificate{
				p: tt.fields.p,
			}
			r.Read(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}

func Test_resourceKeyfactorCertificate_Update(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.UpdateResourceRequest
		response *tfsdk.UpdateResourceResponse
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resourceKeyfactorCertificate{
				p: tt.fields.p,
			}
			r.Update(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}
