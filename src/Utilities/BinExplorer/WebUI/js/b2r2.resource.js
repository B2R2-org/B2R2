const b2r2 = {
  R: {
    tabTemplate: "<li id={3} class='tab active' text-type={0} title={1} counter={2} value={1}><a>{1}</a><span class='glyphicon glyphicon-remove-circle close-tab'></span></li>",
    graphDivTemplate: "<div id='cfgDiv-{0}'><svg id='cfg-{0}' class='box'></svg></div>",
    miniMapTemplate: "<svg id='minimap-{0}' class='box min-box'></svg>",
    functionItemTemplate: "<li title={0}>{0}</li>",
    newWindowTemplate: "<div class='new-main-container' id='id_new-main-container'><div id='id_{0}-graph-container'><div id='cfgDiv-{1}'><svg id='cfg-{1}' class='box'></svg></div></div><div class='minimap-container' id='id_new-minimap-div'></div><div class='new-internel-autocomplete-container'><input id='id_new-address-search' placeholder='Address' type='text' autocomplete='off'><div id='id_new-autocomplete-list' class= 'autocomplete-list'></div></div></div >",
    newWindowHeadTemplate: '<html><head><title>{0}</title><link href="css/bootstrap.min.css" rel="stylesheet" /><link href="css/b2r2.css" rel="stylesheet" /><link href="css/all.min.css" rel="stylesheet" /></head><body>'
  }
}