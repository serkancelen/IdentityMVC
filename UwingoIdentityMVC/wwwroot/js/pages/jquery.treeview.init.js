/*
 Template: Dastone - Bootstrap 5 Admin Dashboard
 Author: Uwingo
 File: Treeview
 */



$(function () {
	"use strict";

	// Default
	$('#jstree').jstree();
	
	//Check Box
	$('#jstree-checkbox').jstree({
		"checkbox" : {
			"keep_selected_style" : false
		  },
		  "plugins" : [ "checkbox" ]
	});
});