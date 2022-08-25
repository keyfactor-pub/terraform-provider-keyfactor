package keyfactor

import (
	"context"
	"github.com/Keyfactor/keyfactor-go-client/api"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"reflect"
	"testing"
)

func Test_dataSourceCertificateType_GetSchema(t *testing.T) {
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
			r := dataSourceCertificateType{}
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

func Test_dataSourceCertificateType_NewDataSource(t *testing.T) {
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
			r := dataSourceCertificateType{}
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

func Test_dataSourceCertificate_Read(t *testing.T) {
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
			r := dataSourceCertificate{
				p: tt.fields.p,
			}
			r.Read(tt.args.ctx, tt.args.request, tt.args.response)
		})
	}
}

func Test_flattenMetadata(t *testing.T) {
	type args struct {
		metadata interface{}
	}
	tests := []struct {
		name string
		args args
		want types.Map
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flattenMetadata(tt.args.metadata); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flattenMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_flattenSANs(t *testing.T) {
	type args struct {
		sans []api.SubjectAltNameElements
	}
	tests := []struct {
		name  string
		args  args
		want  types.List
		want1 types.List
		want2 types.List
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := flattenSANs(tt.args.sans)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flattenSANs() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("flattenSANs() got1 = %v, want %v", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("flattenSANs() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func Test_flattenSubject(t *testing.T) {
	type args struct {
		subject string
	}
	tests := []struct {
		name string
		args args
		want types.Object
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flattenSubject(tt.args.subject); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("flattenSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mapSanIDToName(t *testing.T) {
	type args struct {
		sanID int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapSanIDToName(tt.args.sanID); got != tt.want {
				t.Errorf("mapSanIDToName() = %v, want %v", got, tt.want)
			}
		})
	}
}
