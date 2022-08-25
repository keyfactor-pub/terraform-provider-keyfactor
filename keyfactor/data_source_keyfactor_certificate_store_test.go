package keyfactor

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"reflect"
	"testing"
)

func Test_dataSourceCertificateStoreType_GetSchema(t *testing.T) {
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
			r := dataSourceCertificateStoreType{}
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

func Test_dataSourceCertificateStoreType_NewDataSource(t *testing.T) {
	type args struct {
		ctx context.Context
		p   tfsdk.Provider
	}
	tests := []struct {
		name  string
		args  args
		want  tfsdk.DataSource
		want1 diag.Diagnostics
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dataSourceCertificateStoreType{}
			got, got1 := r.NewDataSource(tt.args.ctx, tt.args.p)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDataSource() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("NewDataSource() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func Test_dataSourceCertificateStore_Read(t *testing.T) {
	type fields struct {
		p provider
	}
	type args struct {
		ctx      context.Context
		request  tfsdk.ReadDataSourceRequest
		response *tfsdk.ReadDataSourceResponse
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
			r := dataSourceCertificateStore{
				p: tt.fields.p,
			}
			r.Read(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}
